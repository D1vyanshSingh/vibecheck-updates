"""Scan service.

Authorization lives here, not in the UI:
  * the caller's own JWT is used to read workspace_members (RLS applies)
  * every source, project, scan and finding is re-checked against that
    workspace, so a client-supplied id from another tenant is a 404
  * privileged writes go through the service role only after that check
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import HTTPException, status

from app.db import SupabaseRest, require_member, require_role, workspace_role
from app.repository import ScanRepository, utcnow
from app.scanners.registry import availability
from app.security import Principal
from app.storage import inspect_zip, sha256, store_source

JOB_KINDS = ["native_secrets", "static_checks", "semgrep", "gitleaks", "osv"]
WRITE_ROLES = ("owner", "admin", "analyst", "developer")
MANAGER_ROLES = ("owner", "admin", "analyst")
READ_ROLES = WRITE_ROLES + ("viewer",)


class ScanService:
    def __init__(self, repo: ScanRepository | None = None) -> None:
        self._repo = repo or ScanRepository()

    async def _role(self, principal: Principal, workspace_id: str) -> str | None:
        return await workspace_role(principal.token, workspace_id)

    async def create_scan(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        project_id: str,
        source_id: str,
        trigger: str = "manual",
    ) -> dict[str, Any]:
        role = await self._role(principal, workspace_id)
        require_role(role, WRITE_ROLES)

        project = await self._repo.get_project(project_id)
        if not project or project.get("workspace_id") != workspace_id:
            raise HTTPException(404, "Project was not found in this workspace.")

        source = await self._repo.get_source(source_id)
        if not source or source.get("project_id") != project_id:
            raise HTTPException(404, "Source snapshot was not found for this project.")

        scan = await self._repo.create_scan(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "source_id": source_id,
                "user_id": principal.id,
                "trigger": trigger,
                "status": "queued",
                "findings_total": 0,
            },
            JOB_KINDS,
        )

        await self._repo.audit(
            {
                "workspace_id": workspace_id,
                "actor_id": principal.id,
                "action": "scan.created",
                "entity_type": "scan",
                "entity_id": scan["id"],
                "metadata": {"trigger": trigger, "project_id": project_id},
            }
        )
        return scan

    async def upload_source(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        project_id: str,
        filename: str,
        data: bytes,
    ) -> dict[str, Any]:
        role = await self._role(principal, workspace_id)
        require_role(role, WRITE_ROLES)

        project = await self._repo.get_project(project_id)
        if not project or project.get("workspace_id") != workspace_id:
            raise HTTPException(404, "Project was not found in this workspace.")

        if not filename.lower().endswith(".zip"):
            raise HTTPException(400, "Only .zip source archives are accepted.")

        info = inspect_zip(data)  # raises ArchiveError -> handled by the API
        path = store_source(workspace_id, project_id, filename, data)

        source = await self._repo.create_source(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "kind": "zip",
                "label": filename.rsplit("/", 1)[-1][:120],
                "storage_path": path,
                "sha256": sha256(data),
                "size_bytes": len(data),
                "file_count": info["file_count"],
                "created_by": principal.id,
            }
        )

        await self._repo.audit(
            {
                "workspace_id": workspace_id,
                "actor_id": principal.id,
                "action": "source.uploaded",
                "entity_type": "project_source",
                "entity_id": source["id"],
                "metadata": {"bytes": len(data), "files": info["file_count"]},
            }
        )
        return source

    async def cancel_scan(
        self, principal: Principal, scan_id: str
    ) -> dict[str, Any]:
        scan = await self._repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(404, "Scan was not found.")

        role = await self._role(principal, scan["workspace_id"])
        require_role(role, MANAGER_ROLES)

        if scan["status"] in ("completed", "failed", "cancelled"):
            raise HTTPException(409, "This scan is already in a terminal state.")

        await self._repo.cancel(scan_id)
        await self._repo.audit(
            {
                "workspace_id": scan["workspace_id"],
                "actor_id": principal.id,
                "action": "scan.cancelled",
                "entity_type": "scan",
                "entity_id": scan_id,
            }
        )
        updated = await self._repo.get_scan(scan_id)
        return updated or scan

    async def request_verification(
        self, principal: Principal, finding_id: str, source_id: str
    ) -> dict[str, Any]:
        finding = await self._repo.get_finding(finding_id)
        if not finding:
            raise HTTPException(404, "Finding was not found.")

        role = await self._role(principal, finding["workspace_id"])
        require_role(role, WRITE_ROLES)

        source = await self._repo.get_source(source_id)
        if not source or source.get("project_id") != finding["project_id"]:
            raise HTTPException(404, "The verification source was not found for this project.")

        run = await self._repo.create_verification(
            {
                "workspace_id": finding["workspace_id"],
                "finding_id": finding_id,
                "status": "pending",
                "requested_by": principal.id,
            }
        )

        scan = await self._repo.create_scan(
            {
                "workspace_id": finding["workspace_id"],
                "project_id": finding["project_id"],
                "source_id": source_id,
                "user_id": principal.id,
                "trigger": "verification",
                "status": "queued",
                "findings_total": 0,
            },
            JOB_KINDS,
        )
        await self._repo.link_verification_scan(run["id"], scan["id"])

        await self._repo.audit(
            {
                "workspace_id": finding["workspace_id"],
                "actor_id": principal.id,
                "action": "verification.requested",
                "entity_type": "finding",
                "entity_id": finding_id,
                "metadata": {"scan_id": scan["id"]},
            }
        )

        return {"verification_run": run, "scan": scan}

    async def assess_url(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        project_id: str,
        source_url: str,
    ) -> dict[str, Any]:
        """Fetch one authorised URL and persist the result as a completed scan.

        The fetch is guarded (see app.assessment.urlguard) and only reads headers
        plus a bounded prefix of the body. Findings are stored through the same
        repository the worker uses, so reports and history see one shape.
        """
        role = await self._role(principal, workspace_id)
        require_role(role, WRITE_ROLES)

        project = await self._repo.get_project(project_id)
        if not project or project.get("workspace_id") != workspace_id:
            raise HTTPException(404, "Project was not found in this workspace.")

        from app.assessment import assess_url as run_assessment

        assessment = await asyncio.to_thread(run_assessment, source_url)
        if assessment.error and not assessment.status_code:
            raise HTTPException(400, assessment.error)

        source = await self._repo.create_source(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "kind": "url",
                "label": (assessment.final_url or assessment.requested_url or source_url)[:120],
                "storage_path": None,
                "sha256": None,
                "size_bytes": assessment.body_bytes,
                "file_count": 0,
                "created_by": principal.id,
            }
        )

        limitations = list(assessment.limitations)
        if assessment.error:
            limitations.append(assessment.error)
        coverage = {
            "scanners": {
                "web_headers": {
                    "status": "ran" if assessment.status_code else "failed",
                    "detail": (
                        f"HTTP {assessment.status_code}; {len(assessment.findings)} header observations"
                        if assessment.status_code
                        else (assessment.error or "The target produced no response.")
                    ),
                }
            },
            "tool_runs": [],
            "technologies": [],
            "limitations": limitations,
            "requested_url": assessment.requested_url,
            "final_url": assessment.final_url,
        }

        now = utcnow()
        scan = await self._repo.create_scan(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "source_id": source["id"],
                "user_id": principal.id,
                "trigger": "manual",
                "status": "completed",
                "started_at": now,
                "completed_at": now,
                "findings_total": len(assessment.findings),
                "coverage": coverage,
            },
            [],
        )

        saved = await self._repo.save_findings(scan, assessment.findings)
        evidence_rows = [
            {
                "workspace_id": workspace_id,
                "finding_id": finding["id"],
                "kind": "scanner_output",
                "file_path": finding.get("file_path"),
                "line_start": finding.get("line_start"),
                "snippet": finding.get("redacted_evidence"),
                "metadata": {
                    "scanner": finding.get("scanner"),
                    "rule_id": finding.get("rule_id"),
                    "final_url": assessment.final_url,
                },
            }
            for finding in saved
            if finding.get("redacted_evidence")
        ]
        await self._repo.add_evidence(evidence_rows)

        await self._repo.audit(
            {
                "workspace_id": workspace_id,
                "actor_id": principal.id,
                "action": "assessment.url.completed",
                "entity_type": "scan",
                "entity_id": scan["id"],
                "metadata": {
                    "project_id": project_id,
                    "final_url": assessment.final_url,
                    "status_code": assessment.status_code,
                    "findings": len(saved),
                },
            }
        )

        return {
            "assessment": assessment.as_dict(),
            "scan": scan,
            "findings": saved,
            "source": source,
        }

    async def import_github_repository(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        project_id: str,
        owner: str,
        repo: str,
        ref: str | None = None,
    ) -> dict[str, Any]:
        """Import a repository archive through the read-only GitHub App.

        Refuses with 503 until the app is actually configured; nothing is
        simulated when credentials are absent.
        """
        role = await self._role(principal, workspace_id)
        require_role(role, WRITE_ROLES)

        project = await self._repo.get_project(project_id)
        if not project or project.get("workspace_id") != workspace_id:
            raise HTTPException(404, "Project was not found in this workspace.")

        from app.integrations.github import GitHubApp, GitHubError

        app = GitHubApp.from_settings()
        if not app.configured:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "The GitHub App is not configured on this deployment, so no repository can be imported.",
            )

        try:
            data = await app.download_zipball(owner, repo, ref)
        except GitHubError as exc:
            raise HTTPException(exc.status_code, exc.message) from exc

        info = inspect_zip(data)
        label = f"{owner}/{repo}" + (f"@{ref}" if ref else "")
        path = store_source(workspace_id, project_id, f"{owner}-{repo}.zip", data)

        source = await self._repo.create_source(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "kind": "github",
                "label": label[:120],
                "storage_path": path,
                "sha256": sha256(data),
                "size_bytes": len(data),
                "file_count": info["file_count"],
                "created_by": principal.id,
            }
        )

        scan = await self._repo.create_scan(
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "source_id": source["id"],
                "user_id": principal.id,
                "trigger": "manual",
                "status": "queued",
                "findings_total": 0,
            },
            JOB_KINDS,
        )

        await self._repo.audit(
            {
                "workspace_id": workspace_id,
                "actor_id": principal.id,
                "action": "github.repository.imported",
                "entity_type": "project_source",
                "entity_id": source["id"],
                "metadata": {
                    "repository": label,
                    "bytes": len(data),
                    "files": info["file_count"],
                    "scan_id": scan["id"],
                },
            }
        )

        return {"source": source, "scan": scan}

    async def run_benchmark(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        corpus_version: str = "v1",
        kinds: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the corpus with the real registry and store the counts."""
        role = await self._role(principal, workspace_id)
        require_role(role, WRITE_ROLES)

        from app.benchmark import corpus_versions, run_corpus

        if corpus_version not in corpus_versions():
            raise HTTPException(422, f"Unknown corpus version: {corpus_version}")

        if kinds:
            allowed = set(self.capabilities()["scanners"])
            unknown = [kind for kind in kinds if kind not in allowed]
            if unknown:
                raise HTTPException(422, f"Unknown scanner kind: {', '.join(unknown)}")

        result = await asyncio.to_thread(run_corpus, corpus_version, kinds or None)
        row = await self._repo.create_benchmark(result.to_row(workspace_id))

        await self._repo.audit(
            {
                "workspace_id": workspace_id,
                "actor_id": principal.id,
                "action": "benchmark.completed",
                "entity_type": "benchmark_run",
                "entity_id": row["id"],
                "metadata": {
                    "corpus_version": corpus_version,
                    "recall": result.as_dict()["recall"],
                    "false_positives": result.false_positives,
                },
            }
        )
        return {"run": row, "result": result.as_dict()}

    async def list_benchmarks(
        self, principal: Principal, *, workspace_id: str, limit: int = 50
    ) -> dict[str, Any]:
        role = await self._role(principal, workspace_id)
        require_member(role)

        db = SupabaseRest(principal.token)  # RLS scopes the rows
        rows = await db.select(
            "benchmark_runs",
            params={
                "workspace_id": f"eq.{workspace_id}",
                "select": "*",
                "order": "created_at.desc",
                "limit": str(max(1, min(limit, 200))),
            },
        )
        return {"runs": rows}

    async def create_report(
        self,
        principal: Principal,
        *,
        scan_id: str,
        report_type: str,
        version: int = 1,
    ) -> dict[str, Any]:
        """Store report metadata; rendering happens on download from stored rows."""
        if report_type not in ("client", "technical"):
            raise HTTPException(422, "Report type must be client or technical.")

        scan = await self._repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(404, "Scan was not found.")

        role = await self._role(principal, scan["workspace_id"])
        require_role(role, READ_ROLES)

        db = SupabaseRest(service=True)
        findings = await db.select(
            "findings", params={"scan_id": f"eq.{scan_id}", "select": "*", "limit": "1000"}
        )

        from app.ai.orchestrator import summarize

        counts = summarize(findings)
        coverage = scan.get("coverage") or {}
        limitations = coverage.get("limitations") if isinstance(coverage, dict) else None
        parts = [
            f"{counts['total']} findings stored for this run",
        ]
        if counts["by_severity"]:
            parts.append(
                "severity: "
                + ", ".join(f"{key} {value}" for key, value in sorted(counts["by_severity"].items()))
            )
        scanners = coverage.get("scanners") if isinstance(coverage, dict) else None
        if isinstance(scanners, dict) and scanners:
            parts.append(
                "checks: "
                + ", ".join(
                    f"{name} {info.get('status', 'unknown')}"
                    for name, info in scanners.items()
                )
            )
        if isinstance(limitations, list) and limitations:
            parts.append(f"coverage limitations: {'; '.join(str(item)[:160] for item in limitations[:3])}")

        report = await self._repo.create_report(
            {
                "workspace_id": scan["workspace_id"],
                "project_id": scan["project_id"],
                "scan_id": scan_id,
                "report_type": report_type,
                "version": version,
                "status": "ready",
                "summary": ". ".join(parts)[:2000],
                "generated_by": principal.id,
            }
        )

        await self._repo.audit(
            {
                "workspace_id": scan["workspace_id"],
                "actor_id": principal.id,
                "action": "report.generated",
                "entity_type": "report",
                "entity_id": report["id"],
                "metadata": {"scan_id": scan_id, "report_type": report_type, "version": version},
            }
        )
        return report

    async def list_findings(
        self,
        principal: Principal,
        workspace_id: str,
        *,
        severity: str | None = None,
        status_filter: str | None = None,
        project_id: str | None = None,
        scanner: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        role = await self._role(principal, workspace_id)
        require_member(role)

        db = SupabaseRest(principal.token)  # RLS scopes the rows
        params: dict[str, str] = {
            "workspace_id": f"eq.{workspace_id}",
            "select": "*",
            "order": "created_at.desc",
            "limit": str(max(1, min(limit, 500))),
            "offset": str(max(0, offset)),
        }
        if severity:
            params["severity"] = f"eq.{severity}"
        if status_filter:
            params["status"] = f"eq.{status_filter}"
        if project_id:
            params["project_id"] = f"eq.{project_id}"
        if scanner:
            params["scanner"] = f"eq.{scanner}"

        rows = await db.select("findings", params=params)
        return {"findings": rows, "total": len(rows), "limit": limit, "offset": offset}

    async def get_finding(
        self, principal: Principal, finding_id: str
    ) -> dict[str, Any]:
        db = SupabaseRest(principal.token)
        rows = await db.select(
            "findings", params={"id": f"eq.{finding_id}", "select": "*", "limit": "1"}
        )
        if not rows:
            raise HTTPException(404, "Finding was not found.")

        evidence = await db.select(
            "finding_evidence",
            params={"finding_id": f"eq.{finding_id}", "select": "*", "limit": "50"},
        )
        return {"finding": rows[0], "evidence": evidence}

    def capabilities(self) -> dict[str, Any]:
        return {"scanners": availability()}


def mark_running(repo: ScanRepository, scan_id: str) -> None:
    """Kept for the worker: a scan moves to running on first job claim."""
    return None


__all__ = ["ScanService", "JOB_KINDS", "utcnow"]
