"""Combine multiple Oracle audit ZIP uploads with system labels."""

from __future__ import annotations

import io
import zipfile
from typing import Any

from linux_audit_engine import run_linux_audit_zip


def process_oracle_uploads(file_entries: list[tuple[Any, str]]) -> dict[str, Any]:
    """
    Process one or more audit ZIP uploads.

    Each entry is (uploaded_file, system_label). Findings and exceptions
    include a ``system`` field for the user-selected label.
    """
    summaries: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    all_exceptions: list[dict[str, Any]] = []

    for file_obj, system_label in file_entries:
        name = getattr(file_obj, 'name', '') or 'upload.zip'
        data = file_obj.read()
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise ValueError(f'Invalid or corrupted ZIP file: {name}')

        payload = run_linux_audit_zip(data)
        summary = dict(payload.get('summary') or {})
        summaries.append(
            {
                'system': system_label,
                'filename': name,
                'hostname': summary.get('hostname', ''),
                'os': summary.get('os', ''),
                'osVersion': summary.get('osVersion', ''),
                'scriptDate': summary.get('scriptDate', ''),
            }
        )

        for finding in payload.get('findings') or []:
            row = dict(finding)
            row['system'] = system_label
            all_findings.append(row)

        for exception in payload.get('exceptions') or []:
            row = dict(exception)
            row['system'] = system_label
            all_exceptions.append(row)

    return {
        'summaries': summaries,
        'summary': summaries[0] if len(summaries) == 1 else {},
        'findings': all_findings,
        'exceptions': all_exceptions,
    }
