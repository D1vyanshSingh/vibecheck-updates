"""Per-finding guidance for the two teams that read a scan report.

A severity, a CWE and a CVSS vector tell a reader how bad something is, but not
what to do next. Every rule therefore carries three fields:

``attack``
    MITRE ATT&CK technique IDs (and their names) that describe what an
    attacker would do with this exposure. They are labels for the report, not
    a claim that the technique was observed.

``detection``
    What a blue team should log or alert on. Written as telemetry that already
    exists in most estates, with the specific field or event ID worth matching,
    so it can be turned into a rule instead of an aspiration.

``next_step``
    The documented validation action for a red team. It is always described,
    never performed by the scanner: the tool stays non-destructive, and
    anything active remains the operator's decision under the engagement's
    authorisation.

The table is keyed by rule_id. Rules the advisory database generates at scan
time (``VS-CVE-YYYY-NNNN``) and any rule without an entry fall back to a family
default, so a new CVE can never render a finding with empty guidance. If a
future rule has no entry, :func:`for_finding` still returns guidance for the
generic case and :data:`GUIDANCE` coverage is checked by the tests.
"""

from __future__ import annotations

from dataclasses import dataclass

# BASELINE RULES
# --------------------------------------------------------------------------

# ATT&CK techniques reused across rules. Named here so the table below stays
# readable and a typo in an ID is caught by the format test, not by a reader.
T1190 = ("T1190", "Exploit Public-Facing Application")
T1210 = ("T1210", "Exploitation of Remote Services")
T1110 = ("T1110", "Brute Force")
T1110001 = ("T1110.001", "Brute Force: Password Guessing")
T1021 = ("T1021", "Remote Services")
T1021001 = ("T1021.001", "Remote Services: Remote Desktop Protocol")
T1021002 = ("T1021.002", "Remote Services: SMB/Windows Admin Shares")
T1021004 = ("T1021.004", "Remote Services: SSH")
T1021005 = ("T1021.005", "Remote Services: VNC")
T1021006 = ("T1021.006", "Remote Services: Windows Remote Management")
T1133 = ("T1133", "External Remote Services")
T1078 = ("T1078", "Valid Accounts")
T1552 = ("T1552", "Unsecured Credentials")
T1552001 = ("T1552.001", "Unsecured Credentials: Credentials In Files")
T1552007 = ("T1552.007", "Unsecured Credentials: Container API")
T1040 = ("T1040", "Network Sniffing")
T1557 = ("T1557", "Adversary-in-the-Middle")
T1046 = ("T1046", "Network Service Discovery")
T1592 = ("T1592", "Gather Victim Host Information")
T1592002 = ("T1592.002", "Gather Victim Host Information: Software")
T1610 = ("T1610", "Deploy Container")
T1611 = ("T1611", "Escape to Host")
T1213 = ("T1213", "Data from Information Repositories")
T1005 = ("T1005", "Data from Local System")
T1039 = ("T1039", "Data from Network Shared Drive")
T1083 = ("T1083", "File and Directory Discovery")
T1059 = ("T1059", "Command and Scripting Interpreter")
T1059007 = ("T1059.007", "Command and Scripting Interpreter: JavaScript")
T1189 = ("T1189", "Drive-by Compromise")
T1539 = ("T1539", "Steal Web Session Cookie")
T1571 = ("T1571", "Non-Standard Port")
T1082 = ("T1082", "System Information Discovery")
T1071 = ("T1071", "Application Layer Protocol")
T1565 = ("T1565", "Data Manipulation")


@dataclass(frozen=True)
class Guidance:
    """What to try (labelled), what to watch for, and how to confirm."""

    attack: tuple[tuple[str, str], ...]
    detection: str
    next_step: str

    def as_dict(self) -> dict:
        return {
            "attack": [{"id": tid, "name": name} for tid, name in self.attack],
            "detection": self.detection,
            "next_step": self.next_step,
        }


def _g(attack: tuple[tuple[str, str], ...], detection: str,
       next_step: str) -> Guidance:
    return Guidance(attack=attack, detection=detection, next_step=next_step)


# Per-rule guidance. Written from each rule's own impact text: the attack
# column names the technique the exposure enables, the detection column names
# telemetry that would show someone using it, and the next step is a read-only
# confirmation an operator can run inside the agreed scope.
GUIDANCE: dict[str, Guidance] = {
    # -- Exposed authentication-bearing services --------------------------
    "VS-EXP-TELNET": _g(
        (T1040, T1021, T1110),
        "Inbound accepts on 23 from outside the management subnets; Telnet "
        "daemon login lines in the host log (`telnetd`, `in.telnetd`) and "
        "interactive-session start events for accounts that normally never "
        "log in remotely.",
        "From an authorised host, confirm the service is Telnet by reading its "
        "IAC negotiation (the scan already did) and identify which accounts "
        "may log in. Do not send credentials unless the engagement's scope "
        "explicitly covers credential testing.",
    ),
    "VS-EXP-TELNET-ALT": _g(
        (T1571, T1040, T1021),
        "A service on a non-standard port negotiating Telnet's IAC bytes "
        "(0xff 0xfb/0xfd); netflow showing long-lived interactive sessions on "
        "the same port pair.",
        "Identify the process behind the port from host configuration rather "
        "than by logging in, and confirm whether it is a documented service "
        "or shadow IT.",
    ),
    "VS-EXP-RDP": _g(
        (T1021001, T1133, T1110001),
        "Windows Security 4625 failures and 4624 logon type 10 bursts against "
        "3389 from a single source, RDP connection events (Zeek `rdp.log`, "
        "Windows TerminalServices operational log), and firewall accepts of "
        "3389 from outside the VPN or management ranges.",
        "From an authorised host, confirm NLA is required and which accounts "
        "may log on over RDP; review the host's RDP exposure in the firewall "
        "config. Credential testing is a separate, explicitly scoped step.",
    ),
    "VS-EXP-SMB": _g(
        (T1021002, T1039, T1110),
        "Windows Security 4625/4776 failures for NTLM against 445, SMB "
        "negotiation events carrying SMBv1 (`\\xffSMB` dialect 0x0001) in "
        "Zeek's `smb_negotiate.log`, and new external sources in NetBIOS/SMB "
        "flow records.",
        "Enumerate the share list anonymously only if the scope allows it "
        "(`smbclient -L`); otherwise confirm from the server configuration "
        "which shares exist and who may reach 445. Do not attempt SMBv1 "
        "exploits outside an isolated lab.",
    ),
    "VS-EXP-VNC": _g(
        (T1021005, T1040, T1110),
        "Inbound accepts on 5900/5901 from non-management sources, VNC "
        "handshake bytes (RFB 003.008) on unexpected port pairs, and repeated "
        "failed VNC authentication in the server's log.",
        "Read the security-type list from the VNC handshake (the scan's probe "
        "does this): security type 1 means no authentication. Do not attempt "
        "a login unless credential testing is in scope.",
    ),
    "VS-EXP-DOCKER-TLS": _g(
        (T1610, T1611, T1552007),
        "Requests to the Docker API on 2376 from hosts that are not the "
        "orchestrator, `dockerd` API access logs, and new container creation "
        "or `docker exec` events originating outside the deployment pipeline.",
        "Confirm the daemon requires client certificates by sending an "
        "unauthenticated `GET /version` (read-only, no state change). Do not "
        "create containers on the client's host.",
    ),
    "VS-EXP-KUBELET": _g(
        (T1610, T1552007),
        "Unauthenticated or anonymous requests to 10250 in the kubelet's "
        "audit/API logs, `pods` or `exec` calls from hosts outside the "
        "control-plane subnets, and 403/401 spikes against the kubelet port.",
        "Fetch `/healthz` and an unauthenticated `/pods` read-only; a 200 "
        "confirms anonymous access without changing cluster state.",
    ),
    "VS-EXP-ETCD": _g(
        (T1552, T1610),
        "etcd client-port traffic on 2379/2380 from non-control-plane hosts, "
        "etcd audit logs showing unauthenticated range requests, and "
        "certificate-less connections where client certs are expected.",
        "Send an unauthenticated `GET /health` and a bounded `/v2/keys` read "
        "(read-only) to confirm whether client certificates are enforced.",
    ),
    "VS-EXP-MYSQL": _g(
        (T1110001, T1190),
        "Authentication failures for the database account in MySQL's error "
        "log, connection attempts on 3306 from outside the application tier, "
        "and `Aborted_clients`/`Access_denied` spikes.",
        "Read the server greeting's version and auth plugin (the scan does "
        "this) and confirm from `bind-address` and the account host grants "
        "which hosts may connect. Do not guess credentials.",
    ),
    "VS-EXP-POSTGRES": _g(
        (T1110001, T1190),
        "`FATAL: password authentication failed` lines in the PostgreSQL "
        "log, connection attempts on 5432 from outside the application subnet, "
        "and `pg_hba.conf` rejections in the log.",
        "Read the ErrorResponse/startup response only; confirm reachability "
        "with a no-credential connection attempt and review `pg_hba.conf` "
        "with the client's DBA.",
    ),
    "VS-EXP-MSSQL": _g(
        (T1110001, T1190),
        "Windows 4625 and MSSQL `18456` login failures on 1433, new external "
        "flow records to 1433, and xp_cmdshell or extended-procedure use in "
        "the SQL audit log.",
        "Confirm the listener is reachable and the authentication mode from "
        "the pre-login response and the server configuration; do not attempt "
        "`sa` guessing.",
    ),
    "VS-EXP-ORACLE": _g(
        (T1110001, T1190),
        "TNS listener traffic on 1521 from non-application hosts, ORA- errors "
        "in the listener log, and repeated CONNECT attempts from one source.",
        "Query the listener's service list read-only (`tnsping`-style "
        "discovery, already covered by the scan) and confirm Valid Node "
        "Checking in `listener.ora`.",
    ),
    "VS-EXP-WINRM": _g(
        (T1021006, T1040, T1110),
        "HTTP requests to 5985 from outside the admin network, WinRM "
        "operational-log shell starts, and 401/500 bursts against the WinRM "
        "endpoint.",
        "Confirm the endpoint answers WS-Management (the scan does) and check "
        "whether HTTPS (5986) is the only advertised listener. Do not send "
        "credentials over plain HTTP.",
    ),
    "VS-EXP-RABBITMQ": _g(
        (T1078, T1110001),
        "Requests to the management UI on 15672, failed logins in the "
        "RabbitMQ log, and queue/connection changes made by unexpected users.",
        "Confirm whether the management plugin requires login by fetching the "
        "UI root unauthenticated; review the plugin's configured listeners.",
    ),
    "VS-EXP-KIBANA": _g(
        (T1213, T1078),
        "Kibana access to 5601 without an authenticated session, saved-object "
        "or index-pattern reads in Kibana's audit log, and new external "
        "sources against the dashboard port.",
        "Confirm whether Kibana redirects to a login or serves the dashboard "
        "to an anonymous client; check the Elasticsearch security "
        "configuration behind it.",
    ),
    "VS-EXP-NFS": _g(
        (T1039, T1005, T1552001),
        "`showmount`-style RPC calls to the portmapper and 2049 from outside "
        "the export-consumer subnet, MOUNT/NFS calls for exports not in the "
        "documented list, and reads of files by clients outside the expected "
        "uid mapping.",
        "List exports read-only (`showmount -e`) where the scope allows it, "
        "and confirm `root_squash`/`all_squash` in `/etc/exports` with the "
        "client.",
    ),
    "VS-EXP-RSYNC": _g(
        (T1039, T1552001),
        "rsync daemon connections on 873 from unexpected hosts, module "
        "listing without authentication, and transfers of paths outside the "
        "documented sync set.",
        "List the daemon's modules read-only (`rsync rsync://host/`) and "
        "confirm `auth users`/`secrets file` in `rsyncd.conf`. Do not start a "
        "transfer.",
    ),
    "VS-EXP-K8S-API": _g(
        (T1610, T1552),
        "API-server requests to 6443 from non-node sources, `system:anonymous` "
        "or unauthenticated subjects in the API audit log, and 403 spikes "
        "from a single client.",
        "Fetch the API server's public discovery document and confirm "
        "anonymous-auth and RBAC from the cluster's own configuration.",
    ),
    "VS-EXP-PROMETHEUS": _g(
        (T1046, T1592002),
        "Scrapes of `/metrics` or `/api/v1/targets` from hosts outside the "
        "monitoring subnet, and first-seen clients against the metrics port.",
        "Read `/api/v1/targets` and a bounded metric sample read-only; it "
        "shows whether authentication is required without changing state.",
    ),
    "VS-EXP-ADMIN": _g(
        (T1133, T1110001),
        "Logins or failed logins against the administrative port from "
        "non-management sources, and interactive-session events that do not "
        "match the change calendar.",
        "Identify the product behind the port from its banner/UI and confirm "
        "whether it is meant to be reachable from the scan source.",
    ),

    # -- Protocol-proof service findings ---------------------------------
    "VS-EXP-REDIS-NOAUTH": _g(
        (T1190, T1059, T1005),
        "Redis `INFO`/`CONFIG`/`MODULE LOAD` commands from a client outside "
        "the application subnet, `MONITOR` output showing unauthenticated "
        "sessions, and Redis `SLOWLOG` entries for administrative commands.",
        "The scan already proved unauthenticated `INFO`; confirm from the "
        "Redis config that `requirepass`/ACLs and `bind` are set. Do not write "
        "keys or load modules.",
    ),
    "VS-EXP-REDIS-AUTH": _g(
        (T1110001, T1552),
        "Redis `NOAUTH`/`WRONGPASS` errors in the server log, repeated `AUTH` "
        "attempts from one client, and new external connections on 6379.",
        "Confirm authentication is enforced (the scan's `INFO` was rejected) "
        "and review password strength/rotation with the owner. No guessing.",
    ),
    "VS-EXP-REDIS": _g(
        (T1110001, T1046),
        "Connections to the Redis port from unexpected sources, and any "
        "`INFO`/`PING` responses served without authentication.",
        "Send one `PING` and observe whether it is answered or rejected; that "
        "distinguishes anonymous access from an auth-protected listener "
        "without sending commands that change data.",
    ),
    "VS-EXP-MEMCACHED-NOAUTH": _g(
        (T1190, T1552),
        "`stats`, `get` and `set` commands from clients outside the "
        "application subnet, UDP traffic on 11211 (reflection), and new "
        "external sources against the memcached port.",
        "The scan's `stats` response already proved anonymous access; confirm "
        "`-l`/`-U 0` binding and SASL settings from the service config.",
    ),
    "VS-EXP-MEMCACHED": _g(
        (T1046, T1552),
        "Memcached connections from unexpected hosts, and amplification "
        "patterns (small UDP request, large reply) in flow data.",
        "Send one `stats` probe and record whether it returns data or an "
        "error; do not store or delete keys.",
    ),
    "VS-EXP-DOCKER": _g(
        (T1610, T1611, T1059),
        "Requests to the Docker API on 2375 from hosts that are not the "
        "orchestrator, `dockerd` API access logs, and container create/exec "
        "events outside the deployment pipeline.",
        "The scan's read-only `GET /version` already proved the API answers "
        "plain HTTP; confirm the daemon's `-H` flags and that the TCP socket "
        "is not bound. Do not create containers.",
    ),
    "VS-EXP-MONGODB": _g(
        (T1190, T1005),
        "MongoDB connections on 27017 from outside the application subnet, "
        "`Authentication failed` entries in the mongod log, and collection "
        "drops/creates by unexpected users.",
        "Read the wire `hello` reply only (the scan does): `authRequired` and "
        "the version are enough to confirm exposure. Do not attempt logins.",
    ),

    # -- FTP --------------------------------------------------------------
    "VS-FTP-ANON": _g(
        (T1133, T1552001, T1005),
        "FTP `USER anonymous` logins, 230 replies to anonymous sessions, and "
        "RETR/LIST volume for the anonymous account in the FTP log.",
        "The scan already confirmed the anonymous login; list the tree "
        "read-only (LIST only, no RETR) if the scope allows, and confirm "
        "`anon_enable`/`anon_upload_enable` with the owner.",
    ),
    "VS-FTP-CLEARTEXT": _g(
        (T1040, T1552),
        "FTP control-channel `USER`/`PASS` commands in cleartext on the wire "
        "(Zeek `ftp.log` records the password field), and AUTH TLS being "
        "absent from the session.",
        "Confirm the server does not offer AUTH TLS by reading the FEAT reply; "
        "do not capture or replay credentials.",
    ),

    # -- TLS --------------------------------------------------------------
    "VS-TLS-EXPIRED": _g(
        (T1557, T1040),
        "Certificate-expiry alerting (or its absence) for this hostname, "
        "clients failing the handshake, and users bypassing the browser "
        "warning in proxy logs.",
        "Confirm the notAfter date from the handshake (the scan already did) "
        "and check the renewal automation. Do not intercept client traffic.",
    ),
    "VS-TLS-NOT-YET-VALID": _g(
        (T1557,),
        "Handshake failures from clients validating notBefore, and clock-skew "
        "or NTP alarms on the host around the deployment time.",
        "Confirm the certificate's notBefore and the host clock offset; "
        "correcting either is a configuration change, not a test.",
    ),
    "VS-TLS-EXPIRING": _g(
        (T1557,),
        "Days-to-expiry metric for the certificate, and the absence of a "
        "renewal job for this hostname.",
        "Confirm the remaining validity from the handshake and check whether "
        "automated renewal (ACME) covers this name.",
    ),
    "VS-TLS-SELF-SIGNED": _g(
        (T1557,),
        "Clients trusting a non-public CA, certificate-pinning exceptions in "
        "browsers, and users clicking through trust warnings.",
        "Confirm the issuer equals the subject (the scan did) and check "
        "whether an internal CA is documented for this service.",
    ),
    "VS-TLS-HOSTNAME": _g(
        (T1557,),
        "Hostname-verification failures in client or proxy logs, and requests "
        "reaching this host under a name missing from the certificate SANs.",
        "Compare the requested name with the SAN list; an additional vhost "
        "may simply need its own certificate.",
    ),
    "VS-TLS-WEAK-CIPHER": _g(
        (T1040, T1557),
        "Handshakes negotiating RC4/3DES/NULL/EXPORT suites in TLS logs or "
        "Zeek `ssl.log`, which modern clients should never select.",
        "Confirm the negotiated suite from the handshake (the scan did) and "
        "review the server's cipher list. Do not attempt to decrypt captured "
        "traffic.",
    ),
    "VS-TLS-LEGACY": _g(
        (T1557, T1040),
        "TLS 1.0/1.1 handshakes in server or Zeek `ssl.log`, and clients "
        "downgrading from TLS 1.2+.",
        "Confirm which protocol versions complete a handshake "
        "(`--legacy-tls` does this) and review the configured minimum version.",
    ),

    # -- HTTP configuration -----------------------------------------------
    "VS-HTTP-HSTS": _g(
        (T1557, T1040),
        "Plain-HTTP requests to a host that should be HTTPS-only, 301s from "
        "`http://` that a client ignores, and SSL-stripping proxies in the "
        "egress path.",
        "Confirm the header is absent on the HTTPS response (the scan did) and "
        "check whether the redirect is enforced at the load balancer.",
    ),
    "VS-HTTP-CSP": _g(
        (T1189, T1059007),
        "Inline-script violations once a report-only CSP exists, and injected "
        "script tags or unexpected third-party script origins in the page.",
        "Confirm the header is absent and review the application's script "
        "inventory; a CSP rollout starts in report-only mode and is not a "
        "scan action.",
    ),
    "VS-HTTP-XFO": _g(
        (T1189,),
        "The page being framed by a third-party origin, and clickjacking "
        "overlays in browser or WAF telemetry.",
        "Confirm both X-Frame-Options and a `frame-ancestors` directive are "
        "absent; the browser console shows the framing error when they are "
        "present.",
    ),
    "VS-HTTP-XCTO": _g(
        (T1059007, T1189),
        "Responses with a mismatched Content-Type being executed as script, "
        "and upload endpoints serving attacker-controlled content.",
        "Confirm `X-Content-Type-Options: nosniff` is missing and review the "
        "upload/content-type handling.",
    ),
    "VS-HTTP-REFPOL": _g(
        (T1552, T1592),
        "Full URLs (with query strings or tokens) appearing in third-party "
        "Referer logs or analytics.",
        "Confirm the header is absent and check whether any URL carries a "
        "secret in its query string.",
    ),
    "VS-HTTP-SERVER-VERSION": _g(
        (T1592002, T1046),
        "Automated scanners requesting version-revealing paths, and the "
        "Server header appearing verbatim in WAF logs.",
        "Confirm the header value (the scan did) and check `server_tokens`/"
        "`ServerTokens` settings; hiding it is hardening, not a test.",
    ),
    "VS-HTTP-POWERED-BY": _g(
        (T1592002,),
        "Framework version strings in response headers reaching untrusted "
        "clients, and stack-specific exploit attempts against the app.",
        "Confirm the header is present and remove it in the framework or "
        "reverse-proxy configuration.",
    ),
    "VS-HTTP-DIR-LISTING": _g(
        (T1083, T1005),
        "200 responses with `Index of /` bodies, directory paths requested "
        "directly, and bulk GETs of files that were never linked.",
        "The scan's response already showed the autoindex page; request one "
        "directory listing read-only to confirm the scope of what is exposed.",
    ),
    "VS-HTTP-STACKTRACE": _g(
        (T1592002, T1083),
        "Exception class names, file paths and SQL fragments in response "
        "bodies captured by the WAF or CDN, and 500 spikes from one client.",
        "Confirm the error page leaks a trace (the scan did) and find the "
        "input that triggers it; reproducing it further is a scoped app test.",
    ),
    "VS-HTTP-COOKIE-NO-SECURE": _g(
        (T1539, T1040),
        "Session cookies appearing on plain-HTTP requests, and the same "
        "cookie value seen by a passive sensor on both schemes.",
        "Confirm the Set-Cookie header lacks Secure (the scan did) and check "
        "whether the site is HTTPS-only at the edge.",
    ),
    "VS-HTTP-COOKIE-NO-HTTPONLY": _g(
        (T1539, T1059007),
        "`document.cookie` reads of the session cookie in client-side code, "
        "and XSS payloads exfiltrating the cookie value.",
        "Confirm the flag is absent and review whether the cookie is "
        "session-bearing or purely cosmetic.",
    ),
    "VS-HTTP-CLEARTEXT": _g(
        (T1040, T1557),
        "Plain-HTTP requests to the service, credentials or tokens in URL "
        "paths, and HTTP 200 responses where HTTPS was expected.",
        "Confirm there is no TLS listener on the port (the scan did) and "
        "check the intended edge configuration.",
    ),

    # -- HTTP management surfaces -----------------------------------------
    "VS-HTTP-ES-OPEN": _g(
        (T1213, T1005, T1565),
        "Unauthenticated `_cluster/health`, `_cat/indices` and `_search` "
        "calls from outside the app subnet, and index deletion or mapping "
        "changes by an unexpected client.",
        "The scan's unauthenticated root request already proved open access; "
        "read `_cluster/health` and the index list read-only to bound what is "
        "exposed. Do not query document contents.",
    ),
    "VS-HTTP-ES-EXPOSED": _g(
        (T1110001, T1190),
        "401/403 responses to unauthenticated Elasticsearch calls, failed "
        "authentication bursts, and new external sources on 9200.",
        "Confirm authentication is enforced (401/403, as the scan saw) and "
        "review which roles the reachable credentials hold.",
    ),
    "VS-HTTP-DOCKER-VERSION": _g(
        (T1610, T1611),
        "Docker API requests on 2375/2376 from non-orchestrator hosts, "
        "container create/exec events outside the pipeline, and daemon "
        "version requests from scanners.",
        "The scan's read-only `GET /version` already proved unauthenticated "
        "API access; confirm the socket binding from the daemon config. Do not "
        "start containers.",
    ),
    "VS-HTTP-ADMIN-OPEN": _g(
        (T1078, T1133),
        "Anonymous 200 responses from a management console, first-seen "
        "clients against the console port, and configuration changes made "
        "outside the change process.",
        "Confirm the console serves content without a login (the scan did) "
        "and identify its product and required auth from the owner's "
        "documentation.",
    ),

    # -- Curated CVE fingerprints -----------------------------------------
    "VS-CVE-2011-2523": _g(
        (T1190, T1059),
        "Outbound shells spawned by the FTP daemon, connections from the host "
        "to an unexpected high port after an FTP login, and the vsftpd "
        "process making a network connection it should never make.",
        "Confirm the banner reports 2.3.4 (the scan did) and verify the "
        "package version on the host. Do not send the trigger username outside "
        "an isolated lab.",
    ),
    "VS-CVE-2021-41773": _g(
        (T1190, T1059, T1083),
        "Encoded traversal (`%2e%2e`, `.%2e`) in request paths, 403/500 "
        "responses to such paths, and unexpected child processes under the "
        "Apache user.",
        "Confirm the build is 2.4.49 and that `mod_cgi` is loaded; request a "
        "harmless traversal path (for example a non-existent dotfile) only in "
        "a scoped test, never a shell payload.",
    ),
    "VS-CVE-2021-42013": _g(
        (T1190, T1059, T1083),
        "The same encoded-traversal patterns as CVE-2021-41773 against a "
        "2.4.50 build, and Apache spawning shell processes.",
        "Confirm the build is 2.4.50 and `mod_cgi` is loaded; verify the "
        "upgrade path to 2.4.51+, which is the actual remediation.",
    ),
    "VS-CVE-2024-6387": _g(
        (T1190, T1059),
        "SSH handshake failures and `LoginGraceTime` timeouts at high volume "
        "from one source, sshd crashes or restarts, and unusual child "
        "processes under `sshd`.",
        "Confirm the OpenSSH build falls in the affected range (the scan's "
        "banner match) and check `LoginGraceTime`. Exploitation attempts are "
        "not part of a scan.",
    ),
    "VS-EOL-SOFTWARE": _g(
        (T1190, T1210),
        "Scans and exploit attempts matching the product's last supported "
        "release, and vendor advisories that no longer list this branch as "
        "fixed.",
        "Confirm the installed release against the vendor's supported-version "
        "matrix and plan the upgrade; no exploitation step is implied.",
    ),
}

# Fallbacks so every generated rule still carries guidance.
_CVE_FALLBACK = _g(
    (T1190, T1210, T1059),
    "Version-specific exploit attempts against the matched service, the "
    "service's own error/crash log around those requests, and a first-seen "
    "client scanning for the advisory's paths.",
    "Confirm the detected product and version (the finding's evidence) and "
    "check the vendor advisory's fixed release. Reproducing the issue is a "
    "separate, explicitly scoped test — the scanner does not attempt it.",
)

_DEFAULT = _g(
    (T1046, T1592002),
    "New external connections to the affected port, and the service's own "
    "authentication or error log for requests from outside the expected "
    "client subnets.",
    "Confirm what the service is from host configuration, then decide whether "
    "it should be reachable from this network at all.",
)


def for_finding(finding) -> dict:
    """Guidance block for one finding, with its source recorded."""
    rule_id = getattr(finding, "rule_id", "") or ""
    entry = GUIDANCE.get(rule_id)
    if entry:
        block = entry.as_dict()
        block["source"] = "rule"
        return block
    if rule_id.startswith("VS-CVE-"):
        block = _CVE_FALLBACK.as_dict()
        block["source"] = "cve-family"
        return block
    block = _DEFAULT.as_dict()
    block["source"] = "default"
    return block


# Findings a red team can act on without first winning a credential: anonymous
# access, unauthenticated management APIs and remotely reachable known-vulnerable
# services. Everything else is context, hardening or an attack that needs a
# foothold already.
_ENTRY_POINT_RULES = frozenset({
    "VS-FTP-ANON",
    "VS-EXP-REDIS-NOAUTH",
    "VS-EXP-MEMCACHED-NOAUTH",
    "VS-EXP-DOCKER",
    "VS-HTTP-DOCKER-VERSION",
    "VS-HTTP-ES-OPEN",
    "VS-HTTP-ADMIN-OPEN",
    "VS-EXP-MONGODB",
    "VS-EXP-KUBELET",
})


def is_entry_point(finding) -> bool:
    """Whether this finding is a credible initial-access candidate.

    Known-vulnerable remote services qualify only when the match is not
    tentative; a distro-build guess is not an entry point until verified.
    """
    rule_id = getattr(finding, "rule_id", "") or ""
    if rule_id in _ENTRY_POINT_RULES:
        return getattr(finding, "confidence", "") != "tentative"
    if rule_id.startswith("VS-CVE-"):
        return (getattr(finding, "severity", "") in ("critical", "high")
                and getattr(finding, "confidence", "") in ("certain", "firm"))
    return False
