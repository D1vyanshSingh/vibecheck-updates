"""VibeCheck HTTP API.

Authentication is a Supabase bearer token; authorization is workspace
membership, checked in the service for every object touched.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.db import SupabaseError
from app.scanners.registry import availability, version_of
from app.security import Principal, get_current_user
from app.service import ScanService
from app.storage import ArchiveError

app = FastAPI(title="VibeCheck API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url] if settings.frontend_url else [],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class ScanCreate(BaseModel):
    workspace_id: str = Field(min_length=1, max_length=64)
    project_id: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=64)
    trigger: str = Field(default="manual", pattern=r"^(manual|push|scheduled)$")


class VerificationCreate(BaseModel):
    source_id: str = Field(min_length=1, max_length=64)


class UrlAssessmentCreate(BaseModel):
    project_id: str = Field(min_length=1, max_length=64)
    source_url: str = Field(min_length=4, max_length=2048)


class ReportCreate(BaseModel):
    report_type: Literal["client", "technical"] = "technical"
    version: int = Field(default=1, ge=1, le=99)


def get_scan_service() -> ScanService:
    """Overridden in tests; a real instance talks to Supabase."""
    return ScanService()


@app.exception_handler(ArchiveError)
async def archive_error(_: Request, exc: ArchiveError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": exc.message, "code": exc.code})


@app.exception_handler(SupabaseError)
async def supabase_error(_: Request, exc: SupabaseError) -> JSONResponse:
    code = 503 if exc.status_code == 503 else 400
    return JSONResponse(status_code=code, content={"detail": exc.message})


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "supabase": settings.supabase_configured,
        "service_role": settings.service_configured,
        "omniroute": settings.omniroute_configured,
        "github": bool(settings.github_app_id),
    }


@app.get("/v1/capabilities")
async def capabilities() -> dict[str, Any]:
    return {
        "scanners": availability(),
        "versions": {name: version_of(name) for name in availability()},
        "limits": {
            "max_zip_bytes": settings.max_zip_bytes,
            "max_extracted_bytes": settings.max_extracted_bytes,
            "max_file_count": settings.max_file_count,
            "scanner_timeout_seconds": settings.scanner_timeout_seconds,
        },
    }


@app.post("/v1/sources", status_code=status.HTTP_201_CREATED)
async def upload_source(
    workspace_id: str = Form(...),
    project_id: str = Form(...),
    file: UploadFile = File(...),
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    data = await file.read()
    source = await service.upload_source(
        principal,
        workspace_id=workspace_id,
        project_id=project_id,
        filename=file.filename or "source.zip",
        data=data,
    )
    return {"source": source}


@app.post("/v1/scans", status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    scan = await service.create_scan(
        principal,
        workspace_id=body.workspace_id,
        project_id=body.project_id,
        source_id=body.source_id,
        trigger=body.trigger,
    )
    return {"scan": scan}


@app.get("/v1/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    principal: Principal = Depends(get_current_user),
) -> dict[str, Any]:
    role = await _role_for_scan(principal, scan_id)
    if not role:
        raise HTTPException(404, "Scan was not found.")

    from app.db import SupabaseRest

    db = SupabaseRest(principal.token)
    rows = await db.select(
        "scans", params={"id": f"eq.{scan_id}", "select": "*", "limit": "1"}
    )
    if not rows:
        raise HTTPException(404, "Scan was not found.")

    jobs = await db.select(
        "scan_jobs",
        params={"scan_id": f"eq.{scan_id}", "select": "*", "order": "kind.asc"},
    )
    return {"scan": rows[0], "jobs": jobs}


@app.post("/v1/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    return {"scan": await service.cancel_scan(principal, scan_id)}


@app.get("/v1/workspaces/{workspace_id}/findings")
async def list_findings(
    workspace_id: str,
    severity: str | None = Query(None, pattern=r"^(critical|high|medium|low|info)$"),
    status_filter: str | None = Query(None, alias="status"),
    project_id: str | None = Query(None),
    scanner: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    return await service.list_findings(
        principal,
        workspace_id,
        severity=severity,
        status_filter=status_filter,
        project_id=project_id,
        scanner=scanner,
        limit=limit,
        offset=offset,
    )


@app.get("/v1/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    return await service.get_finding(principal, finding_id)


@app.post("/v1/findings/{finding_id}/verify", status_code=status.HTTP_201_CREATED)
async def verify_finding(
    finding_id: str,
    body: VerificationCreate,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    return await service.request_verification(principal, finding_id, body.source_id)


WRITE_ROLES = {"owner", "admin", "analyst", "developer"}
READ_ROLES = WRITE_ROLES | {"viewer"}


@app.post("/v1/workspaces/{workspace_id}/url-assessment", status_code=status.HTTP_201_CREATED)
async def assess_website_url(
    workspace_id: str,
    body: UrlAssessmentCreate,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    """Authorized, read-only assessment of a URL the workspace owns.

    The target is guarded before the request and again on every redirect; the
    caller must hold a write role in the workspace. The result is stored as a
    completed scan so it appears in history, findings and reports.
    """
    return await service.assess_url(
        principal,
        workspace_id=workspace_id,
        project_id=body.project_id,
        source_url=body.source_url,
    )


@app.post("/v1/scans/{scan_id}/reports", status_code=status.HTTP_201_CREATED)
async def create_report(
    scan_id: str,
    body: ReportCreate,
    principal: Principal = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    """Record that a report snapshot was generated for a scan.

    Rendering stays in `GET /v1/scans/{id}/report`, which builds the document
    from persisted rows only.
    """
    report = await service.create_report(
        principal,
        scan_id=scan_id,
        report_type=body.report_type,
        version=body.version,
    )
    return {"report": report}


@app.get("/v1/scans/{scan_id}/analysis")
async def analyse_scan(
    scan_id: str,
    principal: Principal = Depends(get_current_user),
) -> dict[str, Any]:
    """Correlation derived from stored rows, plus the plan that was available."""
    from app.ai.orchestrator import correlate, summarize
    from app.ai.omniroute import OmniRoute
    from app.db import SupabaseRest
    from app.scanners.registry import availability

    role = await _role_for_scan(principal, scan_id)
    if role not in READ_ROLES:
        raise HTTPException(404, "Scan was not found.")

    db = SupabaseRest(principal.token)
    scans = await db.select("scans", params={"id": f"eq.{scan_id}", "select": "*", "limit": "1"})
    if not scans:
        raise HTTPException(404, "Scan was not found.")
    scan = scans[0]

    findings = await db.select(
        "findings",
        params={
            "scan_id": f"eq.{scan_id}",
            "select": "id,title,severity,scanner,status,rule_id,file_path,confidence",
            "order": "severity.asc",
            "limit": "500",
        },
    )

    plan = await OmniRoute().plan(
        technologies=(scan.get("coverage") or {}).get("technologies", [])
        if isinstance(scan.get("coverage"), dict)
        else [],
        file_count=len(findings),
        has_lockfiles=False,
    )

    return {
        "scan_id": scan_id,
        "summary": summarize(findings),
        "observations": correlate(findings, scan.get("coverage") or {}),
        "plan": plan.as_dict(),
        "tools_available": availability(),
    }


@app.get("/v1/scans/{scan_id}/report")
async def download_report(
    scan_id: str,
    report_type: Literal["client", "technical"] = Query("technical"),
    output: Literal["json", "html", "pdf"] = Query("json"),
    version: int = Query(1, ge=1, le=99),
    principal: Principal = Depends(get_current_user),
) -> Response:
    """Render a report from stored rows only."""
    from app.db import SupabaseRest
    from app.reports import build_report, render_html, render_json, render_pdf

    role = await _role_for_scan(principal, scan_id)
    if role not in READ_ROLES:
        raise HTTPException(404, "Scan was not found.")

    db = SupabaseRest(principal.token)
    scan_rows = await db.select("scans", params={"id": f"eq.{scan_id}", "select": "*", "limit": "1"})
    if not scan_rows:
        raise HTTPException(404, "Scan was not found.")
    scan = scan_rows[0]

    project_rows = await db.select(
        "projects", params={"id": f"eq.{scan['project_id']}", "select": "*", "limit": "1"}
    )
    workspace_rows = await db.select(
        "workspaces", params={"id": f"eq.{scan['workspace_id']}", "select": "*", "limit": "1"}
    )
    findings = await db.select(
        "findings",
        params={"scan_id": f"eq.{scan_id}", "select": "*", "limit": "1000"},
    )
    evidence_rows = await db.select(
        "finding_evidence",
        params={"workspace_id": f"eq.{scan['workspace_id']}", "select": "*", "limit": "5000"},
    )
    evidence: dict[str, list[dict[str, Any]]] = {}
    for row in evidence_rows:
        evidence.setdefault(row.get("finding_id", ""), []).append(row)

    from app.ai.orchestrator import correlate

    document = build_report(
        report_type=report_type,
        workspace=workspace_rows[0] if workspace_rows else {},
        project=project_rows[0] if project_rows else {},
        scan=scan,
        findings=findings,
        evidence=evidence,
        observations=correlate(findings, scan.get("coverage") or {}),
        version=version,
    )

    if output == "html":
        return Response(content=render_html(document), media_type="text/html; charset=utf-8")
    if output == "pdf":
        return Response(
            content=render_pdf(document),
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="vibecheck-{scan_id}.pdf"'},
        )
    return Response(content=render_json(document), media_type="application/json")


async def _role_for_scan(principal: Principal, scan_id: str) -> str | None:
    from app.db import SupabaseRest, workspace_role

    db = SupabaseRest(principal.token)
    rows = await db.select(
        "scans", params={"id": f"eq.{scan_id}", "select": "workspace_id", "limit": "1"}
    )
    if not rows:
        return None
    return await workspace_role(principal.token, rows[0]["workspace_id"])
