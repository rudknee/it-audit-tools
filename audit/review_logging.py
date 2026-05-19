"""Helpers to persist review run events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from django.http import HttpRequest
from django.utils import timezone

from audit.models import ReviewRunLog


def _client_ip(request: HttpRequest | None) -> str | None:
    if request is None:
        return None
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip() or None
    return request.META.get('REMOTE_ADDR')


def _client_user_agent(request: HttpRequest | None) -> str:
    if request is None:
        return ''
    return (request.META.get('HTTP_USER_AGENT') or '')[:512]


def _duration_ms(started_at: datetime, completed_at: datetime) -> int:
    delta = completed_at - started_at
    return max(0, int(delta.total_seconds() * 1000))


def log_review_run(
    *,
    review_type: str,
    status: str,
    request: HttpRequest | None,
    started_at: datetime,
    session_id: str | uuid.UUID | None = None,
    systems: str = '',
    source_filenames: list[str] | None = None,
    file_count: int = 0,
    input_rows: int | None = None,
    exception_records: int | None = None,
    findings_count: int | None = None,
    exceptions_register_count: int | None = None,
    iapply_filter_applied: bool = False,
    date_format: str = '',
    error_message: str = '',
) -> ReviewRunLog:
    """Write one review run record to the database."""
    completed_at = timezone.now()
    filenames = source_filenames or []
    return ReviewRunLog.objects.create(
        review_type=review_type,
        status=status,
        session_id=uuid.UUID(str(session_id)) if session_id else None,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=_duration_ms(started_at, completed_at),
        systems=(systems or '')[:512],
        source_filenames=', '.join(filenames)[:2000],
        file_count=file_count or len(filenames),
        input_rows=input_rows,
        exception_records=exception_records,
        findings_count=findings_count,
        exceptions_register_count=exceptions_register_count,
        iapply_filter_applied=iapply_filter_applied,
        date_format=(date_format or '')[:8],
        error_message=(error_message or '')[:4000],
        client_ip=_client_ip(request),
        user_agent=_client_user_agent(request),
    )


def log_sql_review_success(
    *,
    request: HttpRequest,
    started_at: datetime,
    session_id: str,
    environments: list[str],
    filenames: list[str],
    total_rows: int,
    exception_records: int,
    iapply_filter_applied: bool,
    date_format: str,
) -> ReviewRunLog:
    return log_review_run(
        review_type=ReviewRunLog.REVIEW_SQL,
        status=ReviewRunLog.STATUS_SUCCESS,
        request=request,
        started_at=started_at,
        session_id=session_id,
        systems=', '.join(sorted(set(environments))),
        source_filenames=filenames,
        file_count=len(filenames),
        input_rows=total_rows,
        exception_records=exception_records,
        iapply_filter_applied=iapply_filter_applied,
        date_format=date_format,
    )


def log_sql_review_failure(
    *,
    request: HttpRequest,
    started_at: datetime,
    session_id: str | None,
    filenames: list[str],
    environments: list[str],
    error_message: str,
    date_format: str = '',
    iapply_filter_applied: bool = False,
) -> ReviewRunLog:
    return log_review_run(
        review_type=ReviewRunLog.REVIEW_SQL,
        status=ReviewRunLog.STATUS_FAILED,
        request=request,
        started_at=started_at,
        session_id=session_id,
        systems=', '.join(sorted(set(environments))),
        source_filenames=filenames,
        file_count=len(filenames),
        iapply_filter_applied=iapply_filter_applied,
        date_format=date_format,
        error_message=error_message,
    )


def log_oracle_review_success(
    *,
    request: HttpRequest,
    started_at: datetime,
    session_id: str,
    filenames: list[str],
    environments: list[str],
    payload: dict[str, Any],
) -> ReviewRunLog:
    findings = payload.get('findings') or []
    exceptions = payload.get('exceptions') or []
    systems = ', '.join(sorted(set(environments)))
    return log_review_run(
        review_type=ReviewRunLog.REVIEW_ORACLE,
        status=ReviewRunLog.STATUS_SUCCESS,
        request=request,
        started_at=started_at,
        session_id=session_id,
        systems=systems[:512],
        source_filenames=filenames,
        file_count=len(filenames),
        findings_count=len(findings),
        exceptions_register_count=len(exceptions),
        error_message='',
    )


def log_oracle_review_failure(
    *,
    request: HttpRequest,
    started_at: datetime,
    session_id: str | None,
    filename: str,
    error_message: str,
) -> ReviewRunLog:
    return log_review_run(
        review_type=ReviewRunLog.REVIEW_ORACLE,
        status=ReviewRunLog.STATUS_FAILED,
        request=request,
        started_at=started_at,
        session_id=session_id,
        source_filenames=[filename] if filename else [],
        file_count=1 if filename else 0,
        error_message=error_message,
    )
