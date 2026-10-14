"""Operator commands that must work without an authenticated API session.

    python -m offensivex.admin create-user --username alice --role admin
    python -m offensivex.admin set-password --username alice
    python -m offensivex.admin run-assessment --assessment-id <uuid> [--report]

There is no default account and no self-registration (ADR-012), so
`create-user` is how the very first admin comes into existence. Passwords are
read from a prompt (or stdin with `--password-stdin`) — never from a
command-line argument, which would land in shell history and process
listings. Every action is written to the audit log with a `cli:<os user>`
actor.

`run-assessment` runs the agent pipeline for a RUNNING assessment with the LLM
configured in the environment (`OFFENSIVEX_LLM_*`); it refuses to run, with an
explanation, if the LLM is not configured.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import uuid
from collections.abc import Sequence

from sqlalchemy.orm import Session, sessionmaker

from offensivex.core.config import Settings, get_settings
from offensivex.core.errors import NotFoundError, OffensiveXError
from offensivex.db import models
from offensivex.db.session import create_db_engine, create_session_factory, session_scope
from offensivex.llm.base import get_llm_provider
from offensivex.services import audit, pipeline
from offensivex.services import reports as reports_service
from offensivex.services import users as users_service
from offensivex.services.assessments import get_assessment


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        # Windows PowerShell prefixes piped text with a UTF-8 BOM; left in, it
        # would silently become part of the password and lock the user out.
        return sys.stdin.readline().lstrip("﻿").rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise OffensiveXError("Passwords do not match.")
    return first


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m offensivex.admin")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user", help="create a user account")
    create.add_argument("--username", required=True)
    create.add_argument("--role", required=True, choices=[r.value for r in models.UserRole])
    create.add_argument("--password-stdin", action="store_true")

    reset = sub.add_parser("set-password", help="set a user's password (ends their sessions)")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password-stdin", action="store_true")

    run = sub.add_parser("run-assessment", help="run the LLM-driven agent pipeline")
    run.add_argument("--assessment-id", required=True, type=uuid.UUID)
    run.add_argument("--report", action="store_true", help="generate a report afterwards")
    return parser


def _create_user(session: Session, args: argparse.Namespace, operator: str) -> None:
    user = users_service.create_user(
        session,
        username=args.username,
        password=_read_password(args.password_stdin),
        role=models.UserRole(args.role),
    )
    audit.record(
        session,
        action="user.create",
        actor_username=operator,
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "role": user.role.value},
    )
    print(f"Created {user.role.value} {user.username!r}.")


def _set_password(session: Session, args: argparse.Namespace, operator: str) -> None:
    found = (
        session.query(models.User)
        .filter_by(username=users_service.normalize_username(args.username))
        .one_or_none()
    )
    if found is None:
        raise NotFoundError(f"No user named {args.username!r}.")
    users_service.set_password(
        session, user_id=found.id, new_password=_read_password(args.password_stdin)
    )
    audit.record(
        session,
        action="user.set_password",
        actor_username=operator,
        target_type="user",
        target_id=found.id,
    )
    print(f"Password updated for {found.username!r}; their sessions were ended.")


def _run_assessment(
    settings: Settings,
    session_factory: sessionmaker[Session],
    args: argparse.Namespace,
    operator: str,
) -> int:
    provider = get_llm_provider(settings)  # raises LLMConfigurationError with the fix
    with session_scope(session_factory) as session:
        assessment = get_assessment(session, args.assessment_id)
        audit.record(
            session,
            action="pipeline.run",
            actor_username=operator,
            target_type="assessment",
            target_id=assessment.id,
            details={"provider": provider.name, "model": getattr(provider, "model", None)},
        )
        session.commit()  # the intent is on record even if the run fails midway
        outcome = pipeline.run_assessment(
            session,
            assessment=assessment,
            llm_provider=provider,
            allow_private_targets=settings.allow_private_targets,
        )
        for stage in outcome.stages:
            mark = "ok  " if stage.succeeded else "FAIL"
            suffix = f" ({stage.error})" if stage.error else ""
            print(f"[{mark}] {stage.agent}{' ' + stage.subject if stage.subject else ''}{suffix}")
        print(f"Assessment {assessment.id} -> {outcome.final_status.value}")

        if args.report:
            report = reports_service.generate_report(
                session, assessment_id=assessment.id, llm_provider=provider
            )
            audit.record(
                session,
                action="report.generate",
                actor_username=operator,
                target_type="report",
                target_id=report.id,
                details={"ai_summary": report.provenance.get("ai_summary", {}).get("status")},
            )
            summary = report.provenance.get("ai_summary", {}).get("status")
            print(f"Report {report.id} (AI summary: {summary})")
    return 0 if not outcome.failures else 3


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = get_settings()
    session_factory = create_session_factory(create_db_engine(settings))
    operator = f"cli:{getpass.getuser()}"

    try:
        if args.command == "run-assessment":
            return _run_assessment(settings, session_factory, args, operator)
        with session_scope(session_factory) as session:
            if args.command == "create-user":
                _create_user(session, args, operator)
            else:
                _set_password(session, args, operator)
    except OffensiveXError as exc:
        print(f"error: {exc.detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
