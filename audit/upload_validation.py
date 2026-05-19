"""Upload filename validation and blocked file-type exclusions."""

from __future__ import annotations

import json
from pathlib import PurePath

# Extensions never accepted on upload (executables, scripts, other archives, etc.)
BLOCKED_EXTENSIONS: frozenset[str] = frozenset(
    {
        '7z',
        'app',
        'asp',
        'aspx',
        'bash',
        'bat',
        'bin',
        'bz2',
        'cmd',
        'com',
        'cpl',
        'csh',
        'deb',
        'dll',
        'dmg',
        'exe',
        'gz',
        'hta',
        'htm',
        'html',
        'img',
        'inf',
        'iso',
        'jar',
        'js',
        'jse',
        'jsp',
        'ksh',
        'lnk',
        'msi',
        'msp',
        'msu',
        'php',
        'phtml',
        'pkg',
        'pl',
        'ps1',
        'psm1',
        'py',
        'pyc',
        'rar',
        'rb',
        'reg',
        'rpm',
        'run',
        'scr',
        'sh',
        'svg',
        'tar',
        'vbe',
        'vbs',
        'wsf',
        'wsh',
        'xhtml',
        'xml',
        'zsh',
    }
)

UPLOAD_PROFILES: dict[str, dict[str, object]] = {
    'csv': {
        'allowed': frozenset({'csv'}),
        'label': 'CSV',
        'accept': '.csv,text/csv,application/vnd.ms-excel',
    },
    'zip': {
        'allowed': frozenset({'zip'}),
        'label': 'ZIP',
        'accept': '.zip,application/zip,application/x-zip-compressed',
    },
}


def _extensions(filename: str) -> list[str]:
    name = PurePath(filename).name.strip()
    if not name or name.startswith('.'):
        return []
    parts = name.split('.')
    if len(parts) < 2:
        return []
    return [part.lower() for part in parts[1:] if part]


def validate_upload_filename(filename: str, profile: str) -> tuple[bool, str | None]:
    """Return (ok, error_message)."""
    if profile not in UPLOAD_PROFILES:
        return False, 'Invalid upload profile.'

    allowed: frozenset[str] = UPLOAD_PROFILES[profile]['allowed']  # type: ignore[assignment]
    label: str = UPLOAD_PROFILES[profile]['label']  # type: ignore[assignment]
    allowed_list = ', '.join(f'.{ext}' for ext in sorted(allowed))

    if not filename or not str(filename).strip():
        return False, 'No filename provided.'

    name = PurePath(filename).name.strip()
    if name.startswith('.'):
        return False, 'Hidden files are not accepted.'

    extensions = _extensions(name)
    if not extensions:
        return False, f'Only {allowed_list} files are accepted.'

    blocked = [ext for ext in extensions if ext in BLOCKED_EXTENSIONS]
    if blocked:
        return False, (
            f'File type not permitted ({", ".join("." + e for e in blocked)}). '
            f'Upload {allowed_list} only.'
        )

    final_ext = extensions[-1]
    if final_ext not in allowed:
        return False, f'Only {allowed_list} files are accepted (got .{final_ext}).'

    if len(extensions) > 1:
        inner_blocked = [ext for ext in extensions[:-1] if ext in BLOCKED_EXTENSIONS]
        if inner_blocked:
            return False, (
                f'File type not permitted ({", ".join("." + e for e in inner_blocked)}). '
                f'Upload {allowed_list} only.'
            )

    return True, None


def upload_rules_json(profile: str) -> str:
    """JSON for embedding in templates (client-side validation)."""
    if profile not in UPLOAD_PROFILES:
        raise ValueError(f'Unknown upload profile: {profile}')
    spec = UPLOAD_PROFILES[profile]
    return json.dumps(
        {
            'allowed': sorted(spec['allowed']),
            'label': spec['label'],
            'accept': spec['accept'],
            'blocked': sorted(BLOCKED_EXTENSIONS),
        }
    )
