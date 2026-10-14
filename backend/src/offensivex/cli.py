"""`offensivex` — the operator CLI (P16).

A thin client over the HTTP API (docs/interfaces/cli.md): every command except
`admin ...` goes through the same authenticated, RBAC-checked, scope-enforcing
routes the dashboard uses. There is no privileged path here — a viewer cannot
launch an assessment from the CLI any more than from the dashboard, and no
command can run a tool against a target except via `assessment run`, which
asks the server to run the normal orchestrator -> agents -> Tool Registry path.

    offensivex status
    offensivex admin create-user --username alice --role admin   # local DB, first admin
    offensivex login --username alice
    offensivex target create --name lab --type web --entry-point http://localhost:8080/
    offensivex authorization submit lab --include domain:localhost@8080 \\
        --attestation "I own this lab" --valid-days 7
    offensivex authorization approve lab 1
    offensivex assessment create lab && offensivex assessment run <id> --wait
    offensivex finding list --assessment <id>
    offensivex report generate <id> --output report.md --format markdown

Secrets: passwords are read from a hidden prompt or stdin (`--password-stdin`),
never from an argument. After `login` only the session token and CSRF token are
kept, in `~/.offensivex/session.json` (override the directory with
`OFFENSIVEX_CLI_HOME`; the file is created owner-only where the OS supports it).
`logout` revokes the session on the server and deletes the file.

Exit codes: 0 ok · 1 request rejected / operation failed · 2 usage error ·
3 not logged in · 4 permission denied · 5 not found · 6 server unreachable or
server error · 7 assessment finished but not fully completed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

import httpx

DEFAULT_API_URL = "http://127.0.0.1:8000"
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_DENIED = 4
EXIT_NOT_FOUND = 5
EXIT_SERVER = 6
EXIT_RUN_ERRORS = 7
_TERMINAL = {"completed", "completed_with_errors", "failed", "cancelled"}


class CliError(Exception):
    def __init__(self, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# --------------------------------------------------------------------------- session store


def _session_path() -> Path:
    home = os.environ.get("OFFENSIVEX_CLI_HOME")
    return (Path(home) if home else Path.home() / ".offensivex") / "session.json"


def _load_session() -> dict[str, Any] | None:
    try:
        data = json.loads(_session_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _save_session(data: dict[str, Any]) -> None:
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with owner-only permissions *before* the token is written.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    if os.name == "nt":
        # The POSIX mode above is a no-op on Windows: drop inherited ACL entries and
        # leave the file readable by its owner only.
        user = os.environ.get("USERNAME", "")
        if user:
            subprocess.run(  # noqa: S603 - fixed argv; icacls ships with Windows
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],  # noqa: S607
                capture_output=True,
                check=False,
            )


def _clear_session() -> None:
    _session_path().unlink(missing_ok=True)


# --------------------------------------------------------------------------- HTTP client


class Api:
    """Holds the base URL + the saved session and turns HTTP failures into
    `CliError`s with an actionable message and the right exit code."""

    def __init__(self, client: httpx.Client, api_url: str) -> None:
        self.client = client
        self.api_url = api_url.rstrip("/")
        self.session = _load_session()
        if self.session and self.session.get("api_url") != self.api_url:
            self.session = None  # a session for another server is not ours to send

    def _headers(self, method: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.session:
            headers["Cookie"] = f"{self.session['cookie_name']}={self.session['token']}"
            if method not in ("GET", "HEAD", "OPTIONS"):
                headers["X-CSRF-Token"] = self.session["csrf_token"]
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        public: bool = False,
        raw: bool = False,
    ) -> Any:
        if not public and not self.session:
            raise CliError("Not logged in. Run `offensivex login` first.", EXIT_AUTH)
        try:
            response = self.client.request(
                method,
                self.api_url + path,
                json=json_body,
                params={k: v for k, v in (params or {}).items() if v is not None},
                headers={} if public else self._headers(method),
            )
        except httpx.HTTPError as exc:
            raise CliError(
                f"Cannot reach the API at {self.api_url} ({type(exc).__name__}). "
                "Is the backend running? Start it with `uvicorn offensivex.main:app`, "
                "or pass --api-url / set OFFENSIVEX_API_URL.",
                EXIT_SERVER,
            ) from exc
        if response.status_code >= 400:
            raise _error_for(response, public=public)
        if raw:
            return response
        if response.status_code == 204 or not response.content:
            return None
        return response.json()


def _error_for(response: httpx.Response, *, public: bool) -> CliError:
    try:
        body = response.json()
        detail = body.get("detail") or body.get("title") or response.reason_phrase
        if isinstance(detail, list):  # request-validation errors
            detail = "; ".join(
                f"{'.'.join(str(p) for p in e.get('loc', [])[1:])}: {e.get('msg')}" for e in detail
            )
    except ValueError:
        detail = response.reason_phrase
    code = response.status_code
    if code == 401:
        if public:  # failed login: the stored session (if any) is unrelated
            return CliError(str(detail), EXIT_AUTH)
        _clear_session()
        return CliError(
            f"{detail} Your session is missing or expired; run `offensivex login`.", EXIT_AUTH
        )
    if code == 403:
        return CliError(f"Permission denied: {detail}", EXIT_DENIED)
    if code == 404:
        return CliError(f"Not found: {detail}", EXIT_NOT_FOUND)
    if code >= 500:
        return CliError(f"Server error ({code}): {detail}", EXIT_SERVER)
    return CliError(f"{detail} (HTTP {code})", EXIT_FAILED)


# --------------------------------------------------------------------------- output helpers


def _out(args: argparse.Namespace, data: Any, human: Callable[[], object]) -> None:
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human()


def _table(rows: list[list[str]], headers: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)))


def _ts(value: str | None) -> str:
    return value[:19].replace("T", " ") if value else "-"


# --------------------------------------------------------------------------- resolvers


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _resolve_target(api: Api, ref: str) -> dict[str, Any]:
    """A target may be given by id or by its (unique) name."""
    if _is_uuid(ref):
        found: dict[str, Any] = api.request("GET", f"/api/v1/targets/{ref}")
        return found
    for target in api.request("GET", "/api/v1/targets"):
        if target["name"] == ref:
            return dict(target)
    raise CliError(
        f"Not found: no target named {ref!r}. See `offensivex target list`.", EXIT_NOT_FOUND
    )


def _parse_rule(text: str, *, exclusion: bool) -> dict[str, Any]:
    """`TYPE:PATTERN[@PORTS]`, e.g. `domain:localhost@8000-8100`, `cidr:10.0.0.0/24@443`."""
    spec, _, ports = text.rpartition("@") if "@" in text else (text, "", "")
    rule_type, sep, pattern = spec.partition(":")
    if not sep or not rule_type or not pattern:
        raise CliError(
            f"Invalid rule {text!r}: expected TYPE:PATTERN[@PORTS], "
            "e.g. domain:localhost@8000-8100",
            EXIT_USAGE,
        )
    rule: dict[str, Any] = {"rule_type": rule_type, "pattern": pattern, "is_exclusion": exclusion}
    if ports:
        rule["ports"] = ports
    return rule


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        # PowerShell prefixes piped text with a UTF-8 BOM; it is not part of the password.
        return sys.stdin.readline().lstrip("﻿").rstrip("\r\n")
    return getpass.getpass("Password: ")


# --------------------------------------------------------------------------- commands


def cmd_status(api: Api, args: argparse.Namespace) -> int:
    health = api.request("GET", "/healthz", public=True)
    try:
        ready: Any = api.request("GET", "/readyz", public=True)
    except CliError as exc:
        ready = {"status": "not ready", "detail": str(exc)}
    system: Any = None
    if api.session:
        try:
            system = api.request("GET", "/api/v1/system/status")
        except CliError as exc:
            system = {"error": str(exc)}
    data = {
        "api_url": api.api_url,
        "health": health,
        "ready": ready,
        "logged_in_as": (api.session or {}).get("username"),
        "system": system,
    }

    def human() -> None:
        print(f"API:        {api.api_url}")
        print(f"Health:     {health.get('status')}")
        print(f"Database:   {ready.get('status')}")
        if not api.session:
            print("Login:      not logged in (run `offensivex login` for configuration details)")
            return
        print(f"Login:      {api.session.get('username')}")
        if system and "error" not in system:
            llm = system["llm"]
            llm_line = (
                f"{llm['provider']} / {llm['model']}"
                if llm["enabled"]
                else "disabled (agents cannot run)"
            )
            print(f"Environment: {system['environment']}")
            print(f"LLM:        {llm_line}")
            print(f"Private targets allowed: {system['allow_private_targets']}")
            print(f"Self-approval allowed:   {system['allow_self_approval']}")
        elif system:
            print(f"System:     {system['error']}")

    _out(args, data, human)
    return EXIT_OK if ready.get("status") == "ok" else EXIT_SERVER


def cmd_login(api: Api, args: argparse.Namespace) -> int:
    username = args.username or input("Username: ").strip()
    password = _read_password(args.password_stdin)
    response = api.request(
        "POST",
        "/api/v1/auth/login",
        json_body={"username": username, "password": password},
        public=True,
        raw=True,
    )
    cookie: SimpleCookie = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookie.load(header)
    if not cookie:
        raise CliError("The server did not return a session cookie.", EXIT_SERVER)
    name, morsel = next(iter(cookie.items()))
    body = response.json()
    _save_session(
        {
            "api_url": api.api_url,
            "cookie_name": name,
            "token": morsel.value,
            "csrf_token": body["csrf_token"],
            "username": body["user"]["username"],
            "role": body["user"]["role"],
            "expires_at": body["expires_at"],
        }
    )
    _out(
        args,
        {"user": body["user"], "expires_at": body["expires_at"]},
        lambda: print(
            f"Logged in as {body['user']['username']} ({body['user']['role']}); "
            f"session expires {_ts(body['expires_at'])}."
        ),
    )
    return EXIT_OK


def cmd_logout(api: Api, args: argparse.Namespace) -> int:
    try:
        if api.session:
            api.request("POST", "/api/v1/auth/logout")
    except CliError as exc:
        if exc.exit_code != EXIT_AUTH:  # an already-expired session is fine to forget
            _clear_session()
            raise
    _clear_session()
    print("Logged out.")
    return EXIT_OK


def cmd_whoami(api: Api, args: argparse.Namespace) -> int:
    me = api.request("GET", "/api/v1/auth/me")
    _out(args, me, lambda: print(f"{me['user']['username']} ({me['user']['role']})"))
    return EXIT_OK


# targets


def cmd_target_create(api: Api, args: argparse.Namespace) -> int:
    body: dict[str, Any] = {
        "name": args.name,
        "type": args.type,
        "default_exposure": args.exposure,
        "default_criticality": args.criticality,
    }
    if args.entry_point:
        body["entry_point"] = args.entry_point
    target = api.request("POST", "/api/v1/targets", json_body=body)
    _out(args, target, lambda: print(f"Created target {target['name']!r} ({target['id']})."))
    return EXIT_OK


def cmd_target_list(api: Api, args: argparse.Namespace) -> int:
    targets = api.request("GET", "/api/v1/targets")
    _out(
        args,
        targets,
        lambda: _table(
            [[t["id"], t["name"], t["type"], t.get("entry_point") or "-"] for t in targets],
            ["ID", "NAME", "TYPE", "ENTRY POINT"],
        ),
    )
    return EXIT_OK


def cmd_target_show(api: Api, args: argparse.Namespace) -> int:
    target = _resolve_target(api, args.target)
    auths = api.request("GET", f"/api/v1/targets/{target['id']}/authorizations")

    def human() -> None:
        print(f"Target:       {target['name']} ({target['id']})")
        print(f"Type:         {target['type']}")
        print(f"Entry point:  {target.get('entry_point') or '(none)'}")
        print(
            f"Exposure:     {target['default_exposure']}   "
            f"Criticality: {target['default_criticality']}"
        )
        print("Authorizations:")
        _print_authorizations(auths)

    _out(args, {**target, "authorizations": auths}, human)
    return EXIT_OK


# authorizations


def _print_authorizations(auths: list[dict[str, Any]]) -> None:
    if not auths:
        print("  (none — submit one with `offensivex authorization submit`)")
    for auth in auths:
        print(
            f"  v{auth['version']}  {auth['status']:<9} valid {_ts(auth['valid_from'])} -> "
            f"{_ts(auth['valid_until'])}"
        )
        for rule in auth.get("scope_rules", []):
            kind = "EXCLUDE" if rule["is_exclusion"] else "include"
            ports = rule.get("ports") or (
                "all ports" if rule["is_exclusion"] else "80,443 (default)"
            )
            print(f"      {kind:<7} {rule['rule_type']}:{rule['pattern']}  ports: {ports}")


def cmd_auth_submit(api: Api, args: argparse.Namespace) -> int:
    if not args.include:
        raise CliError(
            "At least one --include rule is required (scope is default-deny).", EXIT_USAGE
        )
    rules = [_parse_rule(r, exclusion=False) for r in args.include] + [
        _parse_rule(r, exclusion=True) for r in args.exclude
    ]
    target = _resolve_target(api, args.target)
    now = datetime.now(UTC)
    auth = api.request(
        "POST",
        f"/api/v1/targets/{target['id']}/authorizations",
        json_body={
            "scope_rules": rules,
            "attestation": args.attestation,
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=args.valid_days)).isoformat(),
        },
    )
    _out(
        args,
        auth,
        lambda: print(
            f"Submitted authorization v{auth['version']} for {target['name']!r} "
            f"(status: {auth['status']}). An admin must approve it before any assessment can run."
        ),
    )
    return EXIT_OK


def cmd_auth_list(api: Api, args: argparse.Namespace) -> int:
    target = _resolve_target(api, args.target)
    auths = api.request("GET", f"/api/v1/targets/{target['id']}/authorizations")

    def human() -> None:
        print(f"Target {target['name']!r}:")
        _print_authorizations(auths)

    _out(args, auths, human)
    return EXIT_OK


def cmd_auth_decide(api: Api, args: argparse.Namespace) -> int:
    target = _resolve_target(api, args.target)
    auth = api.request(
        "POST", f"/api/v1/targets/{target['id']}/authorizations/{args.version}/{args.decision}"
    )
    _out(
        args,
        auth,
        lambda: print(
            f"Authorization v{auth['version']} for {target['name']!r}: {auth['status']}."
        ),
    )
    return EXIT_OK


# assessments


def _print_assessment(a: dict[str, Any]) -> None:
    print(f"Assessment: {a['id']}")
    print(
        f"Status:     {a['status']}   Mode: {a['scan_mode']}   "
        f"Validation: {a['validation_enabled']}"
    )
    print(f"Started:    {_ts(a['started_at'])}   Finished: {_ts(a['finished_at'])}")
    runs = a.get("agent_runs", [])
    if runs:
        print("Agent runs:")
        for run in sorted(runs, key=lambda r: r.get("created_at") or ""):
            print(f"  {run['agent_type']:<14} {run['status']:<10} attempts={run['attempts']}")
            if run.get("error"):
                print(f"      error: {run['error']}")


def cmd_assessment_create(api: Api, args: argparse.Namespace) -> int:
    target = _resolve_target(api, args.target)
    a = api.request(
        "POST",
        "/api/v1/assessments",
        json_body={
            "target_id": target["id"],
            "scan_mode": args.mode,
            "validation_enabled": args.validate,
        },
    )
    _out(
        args,
        a,
        lambda: print(
            f"Created assessment {a['id']} ({a['status']}). "
            f"Run it with `offensivex assessment run {a['id']}`."
        ),
    )
    return EXIT_OK


def _watch(api: Api, assessment_id: str, args: argparse.Namespace) -> dict[str, Any]:
    deadline = time.monotonic() + args.timeout
    last = ""
    while True:
        a: dict[str, Any] = api.request("GET", f"/api/v1/assessments/{assessment_id}")
        line = (
            a["status"]
            + " "
            + ",".join(f"{r['agent_type']}:{r['status']}" for r in a.get("agent_runs", []))
        )
        if line != last and not args.json:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {line}", file=sys.stderr)
            last = line
        if a["status"] in _TERMINAL:
            return a
        if time.monotonic() > deadline:
            raise CliError(
                f"Timed out after {args.timeout:g}s; the assessment is still {a['status']}. "
                f"Check `offensivex assessment show {assessment_id}`.",
                EXIT_FAILED,
            )
        time.sleep(args.interval)


def cmd_assessment_run(api: Api, args: argparse.Namespace) -> int:
    api.request("POST", f"/api/v1/assessments/{args.assessment}/run")
    if not args.wait:
        print(
            f"Started assessment {args.assessment}. "
            f"Follow it with `offensivex assessment show {args.assessment}`.",
            file=sys.stderr if args.json else sys.stdout,
        )
        return EXIT_OK
    final = _watch(api, args.assessment, args)
    _out(args, final, lambda: _print_assessment(final))
    return EXIT_OK if final["status"] == "completed" else EXIT_RUN_ERRORS


def cmd_assessment_show(api: Api, args: argparse.Namespace) -> int:
    a = api.request("GET", f"/api/v1/assessments/{args.assessment}")
    findings = api.request("GET", f"/api/v1/assessments/{args.assessment}/findings")

    def human() -> None:
        _print_assessment(a)
        print(f"Findings:   {len(findings)}")

    _out(args, {**a, "finding_count": len(findings)}, human)
    return EXIT_OK


def cmd_assessment_list(api: Api, args: argparse.Namespace) -> int:
    items = api.request(
        "GET", "/api/v1/assessments", params={"status": args.status, "limit": args.limit}
    )
    _out(
        args,
        items,
        lambda: _table(
            [
                [
                    i["id"],
                    i["target_name"],
                    i["status"],
                    _ts(i["started_at"]),
                    str(i["finding_count"]),
                ]
                for i in items
            ],
            ["ID", "TARGET", "STATUS", "STARTED", "FINDINGS"],
        ),
    )
    return EXIT_OK


def cmd_assessment_cancel(api: Api, args: argparse.Namespace) -> int:
    a = api.request("POST", f"/api/v1/assessments/{args.assessment}/cancel")
    _out(args, a, lambda: print(f"Assessment {a['id']}: {a['status']}."))
    return EXIT_OK


# findings


def cmd_finding_list(api: Api, args: argparse.Namespace) -> int:
    findings = api.request(
        "GET",
        "/api/v1/findings",
        params={
            "assessment_id": args.assessment,
            "status": args.status,
            "severity": args.severity,
            "limit": args.limit,
        },
    )
    _out(
        args,
        findings,
        lambda: _table(
            [
                [
                    f["id"],
                    f["severity"],
                    f["status"],
                    "-" if f["risk_score"] is None else f"{f['risk_score']:.1f}",
                    f["title"][:60],
                ]
                for f in findings
            ],
            ["ID", "SEVERITY", "STATUS", "RISK", "TITLE"],
        ),
    )
    return EXIT_OK


def cmd_finding_show(api: Api, args: argparse.Namespace) -> int:
    f = api.request("GET", f"/api/v1/findings/{args.finding}")

    def human() -> None:
        print(f"Finding:    {f['id']}")
        print(f"Title:      {f['title']}")
        print(
            f"Severity:   {f['severity']}   Confidence: {f['confidence']:.2f}   "
            f"Status: {f['status']}"
        )
        print(f"Source:     {f['source']}   Component: {f['affected_component'] or '-'}")
        print(f"Asset:      {f.get('asset_identifier') or f['asset_id']}")
        risk = f["risk_score"]
        band = (f.get("risk_breakdown") or {}).get("risk_band")
        print(f"Risk:       {'not scored' if risk is None else f'{risk:.2f} ({band})'}")
        print(f"Seen:       {_ts(f['first_seen'])} -> {_ts(f['last_seen'])}")
        if f.get("description"):
            print(f"\n{f['description']}")
        print(f"\nEvidence ({len(f['evidence'])}):")
        for ev in f["evidence"]:
            print(
                f"  [{ev['kind']}] {_ts(ev['captured_at'])} "
                f"(tool execution {ev['tool_execution_id']})"
            )
            for line in ev["excerpt"].splitlines()[:12]:
                print(f"      {line}")

    _out(args, f, human)
    return EXIT_OK


def cmd_finding_override(api: Api, args: argparse.Namespace) -> int:
    f = api.request(
        "PATCH",
        f"/api/v1/findings/{args.finding}/status",
        json_body={"status": args.status, "reason": args.reason},
    )
    _out(args, f, lambda: print(f"Finding {f['id']} is now {f['status']}."))
    return EXIT_OK


# reports


def _write_report(report: dict[str, Any], fmt: str, output: str | None) -> None:
    if not output:
        return
    out = Path(output)
    if fmt == "json" or (fmt == "both" and out.suffix == ".json"):
        if report.get("content_json") is None:
            raise CliError("This report has no JSON content.", EXIT_NOT_FOUND)
        out.write_text(json.dumps(report["content_json"], indent=2), encoding="utf-8")
    else:
        if report.get("content_markdown") is None:
            raise CliError("This report has no Markdown content.", EXIT_NOT_FOUND)
        out.write_text(report["content_markdown"], encoding="utf-8")
    print(f"Wrote {out}", file=sys.stderr)


def cmd_report_generate(api: Api, args: argparse.Namespace) -> int:
    formats = ["json", "markdown"] if args.format == "both" else [args.format]
    report = api.request(
        "POST", f"/api/v1/assessments/{args.assessment}/reports", json_body={"formats": formats}
    )
    _write_report(report, args.format, args.output)
    summary = {
        k: report[k] for k in ("id", "assessment_id", "formats", "generated_at", "provenance")
    }
    _out(
        args,
        summary,
        lambda: print(f"Generated report {report['id']} ({', '.join(report['formats'])})."),
    )
    return EXIT_OK


def cmd_report_list(api: Api, args: argparse.Namespace) -> int:
    reports = api.request("GET", f"/api/v1/assessments/{args.assessment}/reports")
    _out(
        args,
        reports,
        lambda: _table(
            [[r["id"], ",".join(r["formats"]), _ts(r["generated_at"])] for r in reports],
            ["ID", "FORMATS", "GENERATED"],
        ),
    )
    return EXIT_OK


def cmd_report_get(api: Api, args: argparse.Namespace) -> int:
    report = api.request("GET", f"/api/v1/reports/{args.report}")
    if args.output:
        _write_report(report, args.format, args.output)
    elif args.format == "json":
        print(json.dumps(report["content_json"], indent=2))
    else:
        print(report["content_markdown"] or "")
    return EXIT_OK


# audit


def cmd_audit_list(api: Api, args: argparse.Namespace) -> int:
    entries = api.request(
        "GET", "/api/v1/audit-log", params={"action": args.action, "limit": args.limit}
    )
    _out(
        args,
        entries,
        lambda: _table(
            [
                [_ts(e["occurred_at"]), e["actor_username"] or "-", e["action"], e["outcome"]]
                for e in entries
            ],
            ["WHEN", "ACTOR", "ACTION", "OUTCOME"],
        ),
    )
    return EXIT_OK


# --------------------------------------------------------------------------- parser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="offensivex",
        description="OffensiveX operator CLI. Works against the same API as the dashboard.",
        epilog="Local account setup: `offensivex admin create-user --username NAME --role admin`. "
        "Exit codes: 0 ok, 1 failed, 2 usage, 3 not logged in, 4 denied, 5 not found, "
        "6 server/unreachable, 7 assessment did not complete cleanly.",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("OFFENSIVEX_API_URL", DEFAULT_API_URL),
        help=f"API base URL (env OFFENSIVEX_API_URL; default {DEFAULT_API_URL})",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    sub = parser.add_subparsers(dest="group", required=True, metavar="COMMAND")

    def leaf(
        parent: Any, name: str, func: Callable[..., int], help_: str, example: str = ""
    ) -> argparse.ArgumentParser:
        p = parent.add_parser(
            name, help=help_, description=help_, epilog=f"example: {example}" if example else None
        )
        p.set_defaults(func=func)
        return p

    def group(name: str, help_: str, aliases: Sequence[str] = ()) -> Any:
        return sub.add_parser(name, help=help_, aliases=list(aliases)).add_subparsers(
            dest="cmd", required=True, metavar="ACTION"
        )

    leaf(sub, "status", cmd_status, "show API health and (when logged in) configuration")
    p = leaf(sub, "login", cmd_login, "log in; the password is prompted, never an argument")
    p.add_argument("--username")
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    leaf(sub, "logout", cmd_logout, "revoke the session and forget it locally")
    leaf(sub, "whoami", cmd_whoami, "show the logged-in user")
    sub.add_parser(
        "admin",
        help="local account management: create-user, set-password (direct DB access, no login)",
    )

    target = group("target", "create and inspect targets")
    p = leaf(
        target,
        "create",
        cmd_target_create,
        "create a target",
        "offensivex target create --name lab --type web --entry-point http://localhost:8080/",
    )
    p.add_argument("--name", required=True)
    p.add_argument("--type", default="web")
    p.add_argument("--entry-point", help="http(s) URL where the assessment starts")
    levels = ["low", "medium", "high", "critical"]
    p.add_argument("--exposure", choices=levels, default="medium")
    p.add_argument("--criticality", choices=levels, default="medium")
    leaf(target, "list", cmd_target_list, "list targets")
    p = leaf(target, "show", cmd_target_show, "show a target and its authorizations")
    p.add_argument("target", help="target name or id")

    authz = group("authorization", "submit, inspect and decide scope authorizations", ["auth"])
    p = leaf(
        authz,
        "submit",
        cmd_auth_submit,
        "submit a scope authorization (pending until an admin approves it)",
        "offensivex authorization submit lab --include domain:localhost@8080 "
        '--attestation "I own this lab" --valid-days 7',
    )
    p.add_argument("target", help="target name or id")
    p.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="TYPE:PATTERN[@PORTS]",
        help="in-scope rule, repeatable. TYPE is domain or cidr; PORTS like 8000-8100,443. "
        "Without @PORTS only ports 80/443 are covered.",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TYPE:PATTERN[@PORTS]",
        help="out-of-scope rule, repeatable (wins over includes); without @PORTS, all ports",
    )
    p.add_argument("--attestation", required=True, help="statement that you may assess this target")
    p.add_argument("--valid-days", type=int, default=7)
    p = leaf(authz, "list", cmd_auth_list, "list a target's authorizations and scope rules")
    p.add_argument("target")
    for verb in ("approve", "reject"):
        p = leaf(
            authz,
            verb,
            cmd_auth_decide,
            f"{verb} a pending authorization (admin only; no self-approval by default)",
        )
        p.set_defaults(decision=verb)
        p.add_argument("target")
        p.add_argument("version", type=int)

    assess = group("assessment", "create, run and inspect assessments")
    p = leaf(
        assess, "create", cmd_assessment_create, "create an assessment for an authorized target"
    )
    p.add_argument("target", help="target name or id")
    p.add_argument("--mode", choices=["quick", "standard", "deep"], default="standard")
    p.add_argument("--validate", action="store_true", help="opt in to the Validation Agent")
    p = leaf(
        assess,
        "run",
        cmd_assessment_run,
        "start the agent pipeline on the server",
        "offensivex assessment run <id> --wait",
    )
    p.add_argument("assessment")
    p.add_argument("--wait", action="store_true", help="wait for the run to finish")
    p.add_argument("--timeout", type=float, default=900, help="seconds to wait (default 900)")
    p.add_argument("--interval", type=float, default=3, help="poll interval in seconds")
    p = leaf(assess, "show", cmd_assessment_show, "status, agent runs and failures")
    p.add_argument("assessment")
    p = leaf(assess, "list", cmd_assessment_list, "list recent assessments")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=25)
    p = leaf(assess, "cancel", cmd_assessment_cancel, "cancel an assessment")
    p.add_argument("assessment")

    finding = group("finding", "list and inspect findings")
    p = leaf(finding, "list", cmd_finding_list, "list findings")
    p.add_argument("--assessment")
    p.add_argument("--status")
    p.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("--limit", type=int, default=100)
    p = leaf(finding, "show", cmd_finding_show, "finding detail with evidence and risk")
    p.add_argument("finding")
    p = leaf(finding, "override", cmd_finding_override, "analyst status override (audited)")
    p.add_argument("finding")
    p.add_argument("status", choices=["confirmed", "rejected"])
    p.add_argument("--reason")

    report = group("report", "generate and retrieve reports")
    p = leaf(report, "generate", cmd_report_generate, "generate a report for an assessment")
    p.add_argument("assessment")
    p.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    p.add_argument("--output", "-o", help="write the content to this file")
    p = leaf(report, "list", cmd_report_list, "list an assessment's reports")
    p.add_argument("assessment")
    p = leaf(report, "get", cmd_report_get, "print or save a generated report")
    p.add_argument("report")
    p.add_argument("--format", choices=["json", "markdown"], default="markdown")
    p.add_argument("--output", "-o")

    audit = group("audit", "audit log (admin only)")
    p = leaf(audit, "list", cmd_audit_list, "recent audit entries")
    p.add_argument("--action")
    p.add_argument("--limit", type=int, default=50)
    return parser


def _admin_args(argv: list[str]) -> list[str] | None:
    """If `admin` is the command (after any global options), return what follows it."""
    i = 0
    while i < len(argv):
        if argv[i] == "--json":
            i += 1
        elif argv[i] == "--api-url":
            i += 2
        elif argv[i].startswith("--api-url="):
            i += 1
        else:
            return argv[i + 1 :] if argv[i] == "admin" else None
    return None


def main(
    argv: Sequence[str] | None = None,
    *,
    client_factory: Callable[[], httpx.Client] | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    admin_rest = _admin_args(arguments)
    if admin_rest is not None:
        from offensivex import admin  # local DB operations, no API involved

        if not admin_rest or admin_rest[0] in ("-h", "--help"):
            return admin.main(["--help"])
        return admin.main(admin_rest)
    parser = _build_parser()
    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE
    client = client_factory() if client_factory else httpx.Client(timeout=30.0)
    api = Api(client, args.api_url)
    try:
        return int(args.func(api, args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
