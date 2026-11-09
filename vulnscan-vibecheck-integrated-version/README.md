# vulnscan

A network/service vulnerability scanner written in Python — **standard library
only, zero dependencies** — that produces a proper assessment report: HTML
(styled, printable), JSON (machine-readable) and a colored terminal summary.
The report follows the classic vulnerability-assessment format (modeled on
PurpleSec/Nessus-style sample reports): Executive Summary →
Scan Results → Methodology → Findings grouped by severity → Recommendations,
with an appendix of observed services.

> **What's new in this version.** Identification before judgement, and reports
> that are ready to hand to a client:
>
> - `-r, --report-name NAME` names a report end to end: cover title,
>   `metadata.title` / `metadata.report_name` in the JSON, and the file stem for
>   the HTML, JSON and PDF (`vulnscan-acme-q1_<timestamp>.*`). Report schema is
>   now `1.3`; omitting `-r` behaves exactly as before.
> - The HTML/PDF report has been restyled: cover with KPI cards, finding cards
>   with a two-column evidence layout, dark evidence blocks, and print tuning
>   that cut a 90-finding lab report from 193 pages to 101 without dropping
>   content.
> - Ten new tests cover report naming (295 passing total).
> - Command guide and field card live in `docs/` as printable PDFs, with the
>   same sources mirrored in `vulnscan-update/`.
> - **[How vulnscan works](docs/vulnscan-internals.pdf)** — a 26-page internals
>   handbook: the pipeline, the identity model, the full rule catalogue, the CVSS
>   derivation, the advisory schema, plus a seven-sitting study plan and
>   self-test.

**Field card:** [`vulnscan-cheatsheet.pdf`](vulnscan-cheatsheet.pdf) — every command
on one printable A4 page for use during an engagement. Its source is
[`docs/vulnscan-field-card.html`](docs/vulnscan-field-card.html).

**Internals handbook:** [`docs/vulnscan-internals.pdf`](docs/vulnscan-internals.pdf)
(26 pages) explains how the tool reaches each conclusion; the editable source is
[`docs/vulnscan-internals.html`](docs/vulnscan-internals.html).

## Quick start

```bash
python -m vulnscan scanme.org            # scan + ALL reports, automatically

# that single command writes:
#   out/vulnscan-report_<timestamp>.html   — styled assessment report
#   out/vulnscan-report_<timestamp>.json   — machine-readable findings
#   (your Downloads folder)/vulnscan-report_<timestamp>.pdf — rendered report

# only the summary in the terminal, no files:
python -m vulnscan scanme.org --no-html --no-json --no-pdf

# run fixed, read-only exploit proofs against local vulnlab fixtures only:
python -m vulnscan --lab-exploits

# permanently change where reports are saved (set once, applies forever):
python -m vulnscan --set-output-dir C:\Users\you\Documents\scan-reports
python -m vulnscan --set-pdf-dir C:\Users\you\Documents\scan-reports
python -m vulnscan --show-config        # see what's saved
python -m vulnscan --reset-config       # back to defaults (out/ + Downloads)

# preview the generated report on this machine:
python3 tests/serve_report.py            # → http://127.0.0.1:8622/report.html
```

Targets can be hostnames, IPs or CIDR ranges.

## Usage

```bash
python -m vulnscan <target> [targets...] [options]

# Examples
python -m vulnscan scanme.org                     # default "top" port set
python -m vulnscan 10.0.0.0/29 -p 1-1024          # CIDR + explicit range
python -m vulnscan example.com -p 22,80,8000-8100 --legacy-tls
python -m vulnscan 10.0.0.0/24 --csv                  # + asset CSV in out/
python -m vulnscan 10.0.0.5 -r "ACME Q1 external"      # name the report
python -m vulnscan --version
```

Options:

| Flag | Meaning |
|---|---|
| `-p, --ports` | port spec: `top` (default common-port set), `all` (1–65535), or `22,80,8000-8100` |
| `-t, --timeout` | per-probe timeout seconds (default 2.5) |
| `-c, --concurrency` | max simultaneous probes (default 256) |
| `--legacy-tls` | additionally test for TLS 1.0/1.1 support (slower) |
| `--engine ENGINE` | detection backend: `auto` (default) prefers nmap and falls back to the built-in scanner, `nmap` requires it, `native` never uses it |
| `--version-intensity 2-9` | nmap service-detection effort; lower is faster, higher identifies more (default: nmap's own) |
| *(default)* | HTML + JSON reports land in `out/`, PDF in Downloads — automatically |
| `-o, --output-dir DIR` | directory for the automatic HTML/JSON reports (default: saved config, else `out/`) |
| `--pdf-dir DIR` | directory for the automatic PDF report (default: saved config, else Downloads) |
| `--html PATH` / `--json PATH` / `--pdf PATH` | override the automatic report destination |
| `--csv [PATH]` | write the asset-inventory CSV (default: `out/vulnscan-assets_<timestamp>.csv`); not written unless asked |
| `-r, --report-name NAME` | name this report: the name becomes the report title and the artifact file names (`vulnscan-acme-q1_<timestamp>.html/.json/.pdf`) |
| `--no-html` / `--no-json` / `--no-pdf` | skip that report artifact |
| `-q, --quiet` | no progress output |
| `--no-color` | plain terminal output |
| `--set-output-dir DIR` | **permanently** save DIR as the report directory (one-time command) |
| `--set-pdf-dir DIR` | **permanently** save DIR as the PDF destination (one-time command) |
| `--show-config` | print the saved configuration |
| `--reset-config` | clear saved configuration, back to defaults |

Exit code is `1` when findings exist, `0` when the target is clean — handy for
CI gates.

## What it does

For every open port it collects **evidence first**: TLS certificate (subject,
issuer, SAN, expiry, self-signed-ness, hostname match), service banner
(probe payloads for Redis INFO, memcached stats, SMTP EHLO), and an HTTP probe
(status, headers, server string, title, body snippet). The checks then reason
over that evidence:

* **Exposed services** — Docker API, Redis (auth vs. unauthenticated via the
  INFO probe), memcached, MongoDB, Elasticsearch (checked for open
  cluster access), RDP, SMB, VNC, Telnet, WinRM, kubelet, etcd, database
  listeners, NFS, rsync, RabbitMQ/Kibana consoles and more.
* **Anonymous access** — FTP anonymous logins (banner-aware, works on
  nonstandard FTP ports).
* **TLS** — expired / soon-expiring / not-yet-valid certificates, self-signed,
  hostname mismatch, legacy protocol versions (opt-in), weak ciphers.
* **HTTP configuration** — missing security headers (HSTS, CSP,
  X-Frame-Options, XCTO, Referrer-Policy), server/framework version
  disclosure, enabled directory listing, stack-trace leaks, cookie flags
  (Secure/HttpOnly), plaintext HTTP.
* **Version fingerprints** — known-CVE matching (vsftpd 2.3.4 backdoor,
  Apache 2.4.49/2.4.50 path traversal, OpenSSH regreSSHion range) and
  end-of-life software detection.
* **App-layer verification** — one read-only request per product endpoint
  (Docker, etcd, Kibana, Kubernetes, Prometheus, Elasticsearch, kubelet,
  RabbitMQ) and a MongoDB handshake, so "port 2375 is open" becomes "this
  daemon answered `/version` without authentication".

Normal scans do not exploit targets and send no destructive probes. For
hands-on practice with the companion loopback lab, `python -m vulnscan
--lab-exploits` runs a small set of fixed, read-only proof payloads against
recognized vulnlab fixtures on `127.0.0.1` only (path traversal, the simulated
FTP backdoor, stack-trace disclosure, and a Redis read). The mode accepts no
custom targets and does not modify lab state. It is not a general-purpose
exploit runner; use active testing only within an explicitly authorized lab.

## Detection engines

Service identification can come from one of two backends, and the report says
which one ran:

* **nmap** (preferred when installed) — runs `nmap -sV` for identification,
  parses its XML, then collects the same TLS/banner/HTTP evidence the built-in
  scanner collects. nmap is an **optional external dependency**: it is invoked
  from `PATH` and never bundled, because its licence forbids redistribution
  inside proprietary products.
* **native** (fallback) — the standard-library first-bytes scanner: one
  connection per port, protocol classified from what the service sends (see
  *Native first-bytes identification* below). It is what runs on a machine
  with nothing but Python.

Identification from nmap is used only when nmap actually probed the service
(confidence >= 8). Port-table guesses, `unknown` and `name?` entries are treated
as weak and replaced by what the service said on the wire.

### Advisory database (offline CVE matching)

Version fingerprints are matched against a local SQLite database built from
NVD's CVE JSON 2.0 feeds. `--update-db` downloads the feeds (standard library
only), keeps the last six years by default, and writes the result atomically to
`~/.cache/vulnscan/advisories.sqlite3` (override with `--db` or `VULNSCAN_DB`).
Scans never touch the network: with no database, the built-in fingerprints are
all that runs, and the report says so.

```bash
python -m vulnscan --update-db                        # last six years
python -m vulnscan --update-db --db-years 2021,2024   # or exact years
```

How a match becomes a finding:

* **Ranges, not equality.** NVD's `versionStartIncluding` / `versionEndExcluding`
  are honoured, so Apache 2.4.48–2.4.50 all hit CVE-2021-41773 without three
  hand-written rules. Exact-release CPEs (`...:http_server:2.4.49:...`) are read
  from the criteria string, and `versionEndIncluding` is respected.
* **One finding per CVE.** A CVE listed under several CPEs or ranges is emitted
  once, and the built-in fingerprints win any overlap so a CVE never appears
  twice for the same service.
* **Distro builds are `tentative`.** A package revision (`1.18.0-1ubuntu1`,
  `9.6p1-2ubuntu2`, `-1.el8`) or an nmap extrainfo like `Ubuntu 22.04` means the
  distributor may have backported the fix, so the version range alone cannot
  prove exploitability. The report says so in the finding text.
* **Supported products:** Apache HTTP Server, nginx, OpenSSH, MySQL, MariaDB,
  PostgreSQL, Redis, vsftpd, OpenSSL and PHP — the products the scanner can
  identify with a version. Every other product keeps the curated fingerprint
  rules only.

Limits: NVD coverage depends on its CPE analysis (a published CVE without a CPE
range is not imported); wildcard-only entries with no range are skipped rather
than flagged as affecting every version; and a distro package must be confirmed
against its changelog before being treated as exploitable.

### Verification scripts (NSE)

The nmap engine runs a curated set of **read-only** NSE scripts alongside `-sV`:

| Profile | Scripts | Default |
|---|---|---|
| `safe` | `ssl-cert`, `http-title`, `http-headers`, `smb-os-discovery`, `rdp-ntlm-info`, `docker-version`, `snmp-info` | yes |
| `extended` | the safe set plus `ssl-enum-ciphers`, `ssh-auth-methods`, `http-enum` | no |
| `off` | none | — |

The split follows nmap's own `script.db`: only the first group is tagged `safe`. The
three extended scripts are read-only too, but tagged `intrusive` — many requests,
and a handshake a fragile service may log or drop — so they never run unless asked
for. The `vuln`, `exploit`, `dos` and `brute` categories are never run: they can
crash fragile devices, and a scanner that crashes a service has stopped being
non-destructive.

Script output is used, not just collected. `rdp-ntlm-info`, `smb-os-discovery` and
`docker-version` corroborate `VS-EXP-RDP`, `VS-EXP-SMB` and `VS-EXP-DOCKER`; when a
script proves a service the port only suggested, the finding moves from `tentative`
to `firm`. `ssl-cert` is quoted on certificate findings. Everything else the
scripts observed — including the paid-for `http-title`, `http-headers` and
`http-enum` output — is reproduced in the report's **NSE appendix**, with the
selected script names and the full output kept in the JSON and raw XML. Failed
scripts (`Script execution failed`) are dropped rather than reported as evidence.

### App-layer verification probes

Identification says what a service claims to be; a probe proves it. For the
products where "this port is open" and "anyone can use it" are very different
claims, the scanner makes **one read-only GET** (or one MongoDB handshake)
against an endpoint only that product serves, and keeps the status and a
snippet of what came back:

| Port | Product | Endpoint | A 200 with the product's markers proves |
|---|---|---|---|
| 2375/2376 | Docker | `/version` | daemon answers, no auth required |
| 2379 | etcd | `/health` | key-value store reachable |
| 5601 | Kibana | `/api/status` | console open, version exposed |
| 6443 | Kubernetes API | `/version` | anonymous `/version` access |
| 9090 | Prometheus | `/api/v1/targets` | scrape targets and internal topology exposed |
| 9200 | Elasticsearch | `/_cluster/health` | cluster reachable without auth |
| 10250 | kubelet | `/pods` | pod inventory readable anonymously |
| 15672 | RabbitMQ | `/api/overview` | management API open, version exposed |
| 27017 | MongoDB | `listDatabases` (wire) | database list readable without credentials |

The result is graded, not assumed: a 200 whose body carries the product's
markers upgrades a port-based lead to `certain` and puts the request and the
response in the finding's evidence; a 401/403 proves the product is there but
not that access is anonymous, so the finding stays `firm`; any other status,
a timeout or a page from a different product is discarded rather than reused
as proof. No credentials are sent and nothing is written. A product that does
not speak HTTP is never sent an HTTP request, and a failed probe never
invents a finding.

Probe results are kept per service under `app` in the JSON, and the report's
coverage section lists which products were actually probed.

### A port proposes, the protocol decides

No exposure rule fires on a port number alone. Each service carries an
`identity_source` (`nmap`, `banner`, `http`, or `port`) and the rules treat it as
the difference between evidence and a guess:

| Identification | Port-keyed rules (RDP, SMB, VNC, Redis, Docker, …) |
|---|---|
| Confirmed by nmap `-sV` or a protocol-level banner | reported, `firm` |
| Nothing on the wire identified the service | reported as `tentative`, with the evidence stating it is a port-based lead |
| Identified as a different protocol family (HTTP on 5900, say) | suppressed entirely |

When two strong sources disagree about the protocol (for example nmap says
`ms-wbt-server` while an HTTP probe retrieves a web page) both claims are kept
under `identity_claims` in the JSON, the finding is downgraded to `tentative`,
and the evidence names both sources. The report never silently picks a winner
and then grades the finding as certain.

```bash
python -m vulnscan scanme.org                       # auto: nmap if installed
python -m vulnscan scanme.org --engine native       # built-in scanner only
python -m vulnscan scanme.org --engine nmap         # fail if nmap is missing
python -m vulnscan scanme.org --version-intensity 4 # deeper fingerprinting
python -m vulnscan scanme.org --nse extended        # add the intrusive scripts
python -m vulnscan scanme.org --nse off             # identification only
python -m vulnscan --update-db                      # build/refresh the CVE database
python -m vulnscan scanme.org --db ./advisories.db  # use a specific database
```

### Native first-bytes identification

With no nmap on the machine, identification comes from the wire. The native
engine opens **one connection per port** and classifies from the first bytes the
other side sends; when a service waits to be spoken to, the probe goes out over
that same socket:

| First bytes | Protocol |
|---|---|
| `SSH-` | SSH |
| `HTTP/` | HTTP (parsed on the same connection) |
| `220 (vsftpd` / `220 … ESMTP` | FTP / SMTP |
| `+OK` / `* OK` | POP3 / IMAP |
| `# Server` / `-NOAUTH` | Redis |
| `STAT …` | memcached |
| `RFB 00` | VNC |
| `\xffSMB` / `\xfeSMB` | SMB |
| `\x03\x00\x00` (TPKT) | RDP |
| `@RSYNCD` | rsync |
| MySQL handshake / PostgreSQL message / MongoDB `OP_REPLY` | the matching database |
| `\x16\x03` record | TLS |

Ports that wait for the client get one read-only probe: `INFO` (Redis),
`stats` (memcached), `ruok` (ZooKeeper), `EHLO` (SMTP), a MongoDB `isMaster`
hello, or an X.224 connection request (RDP). Anything still unidentified gets a
single HTTP GET — the same request that exposes a web server squatting on an
unrelated port. TLS ports handshake first and reuse that connection for the
HTTPS request and the certificate.

The only two-connection case is a TLS listener on an unusual port: the plaintext
request earns an alert, which is exactly what tells the engine to retry with a
handshake. On the lab rig the same 21-service scan dropped from 7.5 s to 3.0 s,
with more services identified at protocol level, and every planted protocol is
still recognised with nmap absent from `PATH`.

The JSON report records the engine, its version, the exact argv and privilege
level under `metadata.scan`, so a report can be reproduced later. When the nmap
engine runs, its raw XML is written beside the report as `<report>.nmap.xml`
(next to the HTML when `--no-json` is used) and referenced from
`metadata.scan.raw_xml` — every finding can be traced back to the response nmap
actually received, without embedding megabytes of XML in the report itself.

## Severity model

Severity and confidence are reported independently — a `tentative` finding is
never silently upgraded.

| Severity | Meaning in this report |
|---|---|
| Critical | Exploitable by unauthenticated attackers; often full control (open Redis, Docker API, vsftpd backdoor) |
| High | Meaningful exposure or access (anon FTP, exposed RDP/SMB/VNC, expired cert) |
| Medium | Weaknesses that aid a follow-up attack (missing security headers, legacy TLS, EOL software) |
| Low | Hardening items (version disclosure, self-signed cert, cookie flags) |
| Informational | Observations, not immediate risks |

Confidence: `certain` (the probe directly proved it), `firm` (strong
evidence), `tentative` (needs human verification). Every finding also carries
CWE IDs where applicable, CVE IDs for fingerprint matches, concrete
evidence, a specific remediation and references.

### CVSS

Every finding carries a CVSS 3.1 base score and the vector it was computed
from, and the report shows both. The vector is the source of truth: the score
is calculated from it with the FIRST 3.1 formula, and the severity band is
derived from the score, so a rule cannot claim "high" while the vector scores
5.3. Sources, in order of preference:

| Source | Used for | Report label |
|---|---|---|
| NVD vector | CVE findings imported from the advisory database | `NVD` |
| Curated rule vector | The scanner's own rules, written from each rule's impact text | `rule vector` |
| Band baseline | A rule with no curated vector | `band baseline` |

A band baseline is a triage floor for that severity band, not a claim about a
specific attack path; the report labels it so a reader can tell the difference.
The vector version is reported too (NVD still publishes some CVSS 3.0 scores).

### Red-team and blue-team guidance

Every finding carries three more fields, so one report serves both teams:

| Field | Audience | Content |
|---|---|---|
| `attack[]` | Both | MITRE ATT&CK technique IDs and names — what an attacker would do with the exposure (`T1190`, `T1021.001`, `T1610`, …) |
| `detection` | Blue team | What to log or alert on: the event ID, field or flow that shows someone using it |
| `next_step` | Red team | The documented, read-only validation action — described, never invoked by the scanner |

The guidance table lives in `vulnscan/guidance.py`, keyed by `rule_id`. CVEs
generated by the advisory database use a family fallback (`T1190`, `T1210`,
`T1059` and the advisory's own fix), so no finding can render with empty
guidance. Findings that need no prior foothold — anonymous access,
unauthenticated management APIs, remotely reachable known-vulnerable services —
are also flagged `entry_point: true` and grouped under **Initial access
candidates** in the report, so a red team does not read forty cards to find the
three that matter. A tentative CVE match is never marked as an entry point
until its version is verified.

### Asset inventory CSV

`--csv` writes one row per open service — `host`, `ip`, `port`, `protocol`,
`service`, `product`, `version`, `cpe`, `identified_by`, `tls`, `state`, plus
finding counts (`findings`, `critical`, `high`) — as RFC 4180 CSV. Multiple
CPEs are joined with `;`. It opens directly in a spreadsheet, and is what both
teams import into their own tooling rather than copying from the PDF.

## Report format

The HTML report mirrors standard vulnerability assessment reports:

1. **Scope and authorisation** — targets, ports, scan window, explicit non-goals
2. **Coverage and provenance** — the engine and version that actually ran, the
   exact command, privileges, NSE scripts, timeouts, advisory database, which
   open ports could not be identified, and the raw-output path, so the scan can
   be reproduced rather than trusted
3. **Executive summary** — context prose + severity counts with CVSS ranges
4. **Asset inventory** — every observed host and service with CPE and how it
   was identified (banner, protocol probe, nmap guess)
5. **Per-host rollup** — one block per host: what is running, what is wrong
   with it, and the three fixes to do first
6. **Findings** — initial-access candidates first, then grouped by severity
   band with per-band framing, followed by detailed cards (asset, CVSS score
   and vector, description, impact, ATT&CK techniques, blue-team detection
   guidance, red-team validation step, evidence, remediation, CWE/CVE)
7. **Recommendations** — de-duplicated actions ranked by number of findings
   resolved and hosts affected
8. **Methodology and limits** — how each confidence and CVSS value was assigned
9. **Appendix** — NSE script output, then all observed services with banners

The JSON uses the same content with a `report_version` (currently `1.2`; the
1.2 additions are the per-finding `attack`/`detection`/`next_step` guidance and
`entry_point`, 1.1 added `coverage` and the per-finding `cvss` block, and every
earlier key keeps its meaning), `metadata`, `scope`, `summary`, `services[]`
and `findings[]`. Each finding looks like:

```json
{
  "id": "VS-0001",
  "rule_id": "VS-CVE-2011-2523",
  "title": "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
  "severity": "critical",
  "confidence": "certain",
  "status": "open",
  "cwe": ["CWE-912"],
  "cve": ["CVE-2011-2523"],
  "asset": { "host": "192.0.2.10", "ip": "192.0.2.10", "port": 21,
             "protocol": "tcp", "service": "ftp" },
  "description": "The banner identifies vsftpd 2.3.4 …",
  "impact": "Trivial remote code execution as the FTP server user.",
  "evidence": "Banner: '220 (vsFTPD 2.3.4)'",
  "remediation": "Reinstall a current vsftpd release immediately …",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
  "cvss": {
    "score": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "version": "3.1",
    "band": "critical",
    "source": "rule"
  },
  "attack": [
    { "id": "T1190", "name": "Exploit Public-Facing Application" },
    { "id": "T1059", "name": "Command and Scripting Interpreter" }
  ],
  "detection": "Outbound shells spawned by the FTP daemon …",
  "next_step": "Confirm the banner reports 2.3.4 (the scan did) …",
  "entry_point": true,
  "provenance": { "scanner": "vulnscan 0.1.0", "guidance": "rule" }
}
```

Fields are omitted rather than invented: a finding without a CVE lists no
CVE content, and unknown certificate fields stay empty.

The report object also carries a top-level `coverage` block (engine, exact
command, scan source, skipped ports, advisory database, `unidentified` ports
with the reason each one gave, and what was not tested), which is what the
*Coverage and provenance* section renders.

A port that accepts the connection and then resets or says nothing — nmap calls
it `tcpwrapped` — is reported as **not identified** rather than named from the
port table, and it is listed in `coverage.unidentified`. The same note appears
at the end of the CLI run, so "0 findings" is never read as "nothing there".

### Sample report

This representative excerpt comes from the deliberately vulnerable **local test
rig** (`127.0.0.1`), not a real-world assessment:

| Scan overview | Result |
|---|---:|
| Ports scanned | 7 |
| Open services | 7 |
| Total findings | 25 |
| Critical / High / Medium / Low / Informational | 5 / 1 / 4 / 11 / 4 |

**VS-0001 · Critical · Certain** — *vsftpd 2.3.4 backdoor (CVE-2011-2523)*

- **Affected service:** `127.0.0.1:2121/tcp` (FTP)
- **Evidence:** `220 (vsFTPD 2.3.4)`
- **Impact:** Remote code execution as the FTP server user.
- **Recommendation:** Reinstall a current vsftpd release and audit the host
  for signs of compromise.

**[Open the full sample PDF report](sample-report.pdf)** — an eight-page report
from the local test rig, including the complete findings, recommendations and
observed services.

The generated HTML report presents the same information in a styled, interactive
format.

## Testing

`python3 tests/fake_services.py` starts a rig of deliberately vulnerable fake
services on loopback (open Redis, no-auth memcached, anonymous vsftpd 2.3.4,
plain HTTP, self-signed HTTPS, plain-HTTP Docker API). Then:

```bash
python -m vulnscan 127.0.0.1 -p 21,6379,11211,8080,8443,2375
```

Reports are automatic — this one command produces the HTML, JSON and the
Downloads-folder PDF with no extra flags.

### Rule test suite

Every rule ships with two cases in `tests/test_rule_matrix.py`: a fixture that
plants the weakness must produce the finding at the documented severity and
confidence, and a nearby fixture without it must produce no such finding. The
matrix is pinned to the rule registry (`58 rules → 116 cases`), so a new rule
ID without a case — or a severity changed without its case — fails
`test_matrix_covers_every_rule_id` instead of silently shipping untested.

```bash
python3 -m unittest tests.test_rule_matrix    # 120 tests: 116 cases + 4 coverage checks
python3 -m unittest tests.test_probes        # app-layer probe semantics (200/401/404/wrong product)
python3 -m unittest tests.test_sniffer       # first-bytes classification + connections per port
```

## Layout

```
vulnscan/
  targets.py   # target + port spec parsing
  scanner.py   # async connect scan, banner/TLS/HTTP probes
  engines/     # detection backends: nmap (optional) or the built-in scanner
  checks.py    # rule engine → Finding objects
  advisories.py # offline SQLite CVE database and version-range matching
  cvss.py      # CVSS 3.1 vectors → base scores
  guidance.py  # per-rule ATT&CK technique, detection and validation step
  report.py    # JSON / HTML / terminal rendering
  pdf.py       # headless-browser PDF rendering (auto-download)
  cli.py       # argparse front end
tests/
  fake_services.py     # vulnerable mock services for verification
  test_sniffer.py      # first-bytes classification and connection counts
  test_rule_matrix.py  # positive + negative case for every rule ID
  test_probes.py       # app-layer probe and MongoDB handshake behaviour
  serve_report.py      # static preview server for out/report.html
```

## Limits

Banner-based detection can mislabel services; confidence is tracked per rule
and `tentative` findings say so explicitly. Version fingerprinting only fires
when the service discloses a version. This is a surface scanner, not a
replacement for an authenticated patch audit.

CVSS scores are truthful about their source but not all equally specific: NVD
vectors describe the CVE, while a band baseline describes only the severity
band. Use the score to rank and the vector text to decide — and treat a
`tentative` finding's score as provisional, because the finding itself is.

The ATT&CK techniques describe what the exposure would enable, not what was
observed. The validation step is a description of a safe confirmation, not an
action the scanner took: `--strict`, `--lab-exploits` and everything else in
this tool remain non-destructive.
