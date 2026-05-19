"""
Linux audit ZIP parsing, findings, and exceptions register generation.

Ported from templates/linux_audit.html (client JS) for server-side processing.
"""

from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
from typing import Any

_NON_INTERACTIVE_SHELLS = frozenset(
    {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false"}
)

# Aligns with CAAT / linux_audit_exceptions.py-style thresholds where applicable.
_PASS_MAX_DAYS_THRESHOLD = 365
_STALE_ACCOUNT_DAYS = 180
_PASSWD_MAX_MODE = 0o644
_SHADOW_MAX_MODE = 0o640
_SENSITIVE_PATH_PREFIXES = (
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/etc",
    "/var/spool/cron",
    "/var/log",
    "/root",
)
_INTERACTIVE_SHELLS_CAAT = frozenset(
    {
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/usr/bin/sh",
        "/bin/zsh",
        "/usr/bin/zsh",
        "/bin/ksh",
        "/usr/bin/ksh",
    }
)
_NON_LOGIN_SHELL_MARKERS_CAAT = ("nologin", "false", "sync", "shutdown", "halt")
_PAM_FILENAMES = (
    "system-auth.txt",
    "password-auth.txt",
    "common-auth.txt",
    "common-password.txt",
    "loginpassword.txt",
    "sshdPassword.txt",
)
_RE_LOGIN_DEF = re.compile(r"^\s*([A-Z_]+)\s+(\S+)")


def _is_caat_interactive_shell(shell: str | None) -> bool:
    """Same idea as IT-Audit CAAT parser: known interactive shells or not a nologin/false-style shell."""
    s = (shell or "").strip()
    if not s:
        return False
    if s in _INTERACTIVE_SHELLS_CAAT:
        return True
    return not any(m in s.lower() for m in _NON_LOGIN_SHELL_MARKERS_CAAT)


def _parse_octal_mode(mode: object) -> int | None:
    try:
        return int(str(mode).strip(), 8)
    except (TypeError, ValueError):
        return None


def _scan_pam_stack(pam_stack: dict[str, str]) -> tuple[bool, bool, list[str]]:
    """Return (faillock_or_tally_seen, pwquality_family_seen, nullok_evidence_lines)."""
    faillock = False
    pwq = False
    nullok: list[str] = []
    for fname, content in pam_stack.items():
        for raw in content.split("\n"):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if "pam_faillock.so" in low or "pam_tally" in low:
                faillock = True
            if "pam_pwquality.so" in low or "pam_passwdqc.so" in low or "pam_cracklib.so" in low:
                pwq = True
            if "pam_unix.so" in low and re.search(r"\bnullok\b", low):
                nullok.append(f"{fname}: {line[:240]}")
    return faillock, pwq, nullok


def _safe_int(s: str | None) -> int | None:
    if s is None or s == "":
        return None
    try:
        return int(s, 10)
    except ValueError:
        return None


def _zip_read_text(zf: zipfile.ZipFile, filename: str) -> str | None:
    """Read UTF-8 text from ZIP member; return None if missing."""
    try:
        with zf.open(filename) as f:
            return f.read().decode("utf-8", errors="replace")
    except KeyError:
        return None


def parse_audit_last_login_timestamp(s: str | None) -> datetime | None:
    """Parse last(1)-style strings; return naive datetime only when trustworthy."""

    if not s or not isinstance(s, str):
        return None
    t = s.strip()
    if not t:
        return None

    def _year_ok(d: datetime) -> datetime | None:
        if d.year < 1990 or d.year > 2100:
            return None
        return d

    # ISO-like prefix (similar to JS new Date(t) for parseable ISO strings)
    if len(t) >= 10 and t[4] == "-" and t[7] == "-":
        try:
            if len(t) >= 19 and t[10] in ("T", " "):
                d = datetime.strptime(t[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
            else:
                d = datetime.strptime(t[:10], "%Y-%m-%d")
            return _year_ok(d)
        except ValueError:
            pass

    m1 = re.match(
        r"^(\d{1,2})-(\d{1,2})-(\d{2,4})(?:\s+(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?",
        t,
    )
    if m1:
        day, month, yr_s = int(m1[1]), int(m1[2]), int(m1[3])
        yr = yr_s + 2000 if yr_s < 100 else yr_s
        hh = int(m1[4]) if m1[4] is not None else 0
        mm = int(m1[5]) if m1[5] is not None else 0
        ss = int(m1[6]) if m1[6] is not None else 0
        try:
            d = datetime(yr, month, day, hh, mm, ss)
            if d.month != month:
                return None
            return _year_ok(d)
        except ValueError:
            pass

    m2 = re.match(
        r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:\s+(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?",
        t,
    )
    if m2:
        day, month, yr = int(m2[1]), int(m2[2]), int(m2[3])
        hh = int(m2[4]) if m2[4] is not None else 0
        mm = int(m2[5]) if m2[5] is not None else 0
        ss = int(m2[6]) if m2[6] is not None else 0
        try:
            d = datetime(yr, month, day, hh, mm, ss)
            if d.month != month:
                return None
            return _year_ok(d)
        except ValueError:
            pass

    m3 = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})(?:[T\s](\d{2}):(\d{2})(?::(\d{2}))?)?",
        t,
    )
    if m3:
        yr, month, day = int(m3[1]), int(m3[2]), int(m3[3])
        hh = int(m3[4]) if m3[4] is not None else 0
        mm = int(m3[5]) if m3[5] is not None else 0
        ss = int(m3[6]) if m3[6] is not None else 0
        try:
            d = datetime(yr, month, day, hh, mm, ss)
            if d.month != month:
                return None
            return _year_ok(d)
        except ValueError:
            pass

    return None


def parse_audit_zip(data: bytes) -> dict[str, Any]:
    """Parse Linux audit ZIP bytes into the same structure as the former JS parser."""
    result: dict[str, Any] = {
        "summary": {},
        "systemInfo": {},
        "sshdConfig": {},
        "passwordQuality": {},
        "faillockConfig": {},
        "users": [],
        "passwords": {},
        "passwordRecords": [],
        "loginDefs": {},
        "pamStack": {},
        "metadataEntries": [],
        "passwordQualityFilePresent": False,
        "lastLogin": {},
        "riskyServices": "",
        "rhosts": "",
        "sudoers": "",
    }

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        # SystemInformation.txt
        sys_content = _zip_read_text(zf, "SystemInformation.txt")
        if sys_content:
            lines = [ln for ln in sys_content.split("\n") if ln.strip()]
            if len(lines) >= 2:
                headers = [h.strip() for h in lines[0].split(";")]
                values = [v.strip() for v in lines[1].split(";")]
                for i, raw_key in enumerate(headers):
                    if i >= len(values) or not values[i]:
                        continue
                    v = values[i]
                    key = raw_key.lower().replace(" ", "")
                    result["systemInfo"][raw_key] = v
                    if "hostname" in key or key == "host" or "nodename" in key:
                        result["summary"]["hostname"] = v
                    elif (
                        ("os" in key or "operatingsystem" in key or key == "distribution")
                        and "version" not in key
                        and "kernel" not in key
                    ):
                        result["summary"]["os"] = v
                    elif "osversion" in key or "release" in key or (
                        "version" in key and ("os" in key or "kernel" in key)
                    ):
                        result["summary"]["osVersion"] = v
                    elif (
                        "scriptdate" in key
                        or "collectiondate" in key
                        or "auditdate" in key
                        or "rundate" in key
                        or ("date" in key and ("script" in key or "scan" in key))
                    ):
                        result["summary"]["scriptDate"] = v

        sshd_content = _zip_read_text(zf, "Sshdconfig.txt")
        if sshd_content:
            directives = [
                "PermitRootLogin",
                "PasswordAuthentication",
                "PubkeyAuthentication",
                "PermitEmptyPasswords",
                "MaxAuthTries",
                "MaxSessions",
                "ClientAliveInterval",
                "ClientAliveCountMax",
                "LoginGraceTime",
                "Banner",
                "AllowTcpForwarding",
                "X11Forwarding",
                "HostbasedAuthentication",
            ]
            for line in sshd_content.split("\n"):
                trimmed = line.strip()
                if not trimmed or trimmed.startswith("#"):
                    continue
                for d in directives:
                    m = re.match(rf"^\s*{re.escape(d)}\s+(.+)$", trimmed, re.I)
                    if m:
                        result["sshdConfig"][d] = m.group(1).strip()

        pwq = _zip_read_text(zf, "passwordquality.txt")
        if pwq is not None:
            result["passwordQualityFilePresent"] = True
        if pwq:
            mm = re.search(r"minlen\s*=\s*(\d+)", pwq, re.I)
            if mm:
                result["passwordQuality"]["minlen"] = int(mm.group(1))
            ms = re.search(r"maxsequence\s*=\s*(\d+)", pwq, re.I)
            if ms:
                result["passwordQuality"]["maxsequence"] = int(ms.group(1))
            result["passwordQuality"]["enforce_for_root"] = bool(
                re.search(r"enforce_for_root", pwq, re.I)
            )

        fail = _zip_read_text(zf, "faillockconfig.txt")
        if fail:
            dm = re.search(r"deny\s*=\s*(\d+)", fail, re.I)
            if dm:
                result["faillockConfig"]["deny"] = int(dm.group(1))
            um = re.search(r"unlock_time\s*=\s*(\d+)", fail, re.I)
            if um:
                result["faillockConfig"]["unlock_time"] = int(um.group(1))

        users_txt = _zip_read_text(zf, "Userinformation.txt")
        if users_txt:
            for line in users_txt.split("\n"):
                if not line.strip():
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    result["users"].append(
                        {
                            "name": parts[0],
                            "uid": int(parts[2]) if parts[2].isdigit() else 0,
                            "gid": int(parts[3]) if parts[3].isdigit() else 0,
                            "gecos": parts[4],
                            "home": parts[5],
                            "shell": parts[6],
                        }
                    )

        pwd_txt = _zip_read_text(zf, "Passwordinformation.txt")
        if pwd_txt:
            for line in pwd_txt.split("\n"):
                trimmed = line.strip()
                if not trimmed or trimmed.startswith("#"):
                    continue
                parts = trimmed.split(":")
                while len(parts) < 9:
                    parts.append("")
                username = parts[0].strip()
                if not username:
                    continue
                lock_s = parts[7].strip()
                pass_stat = parts[8].strip()
                result["passwordRecords"].append(
                    {
                        "user": username,
                        "lock_status": lock_s,
                        "password_status": pass_stat,
                        "min_days": parts[2].strip(),
                        "max_days": parts[3].strip(),
                        "line": trimmed,
                    }
                )
                if re.search(r"Locked", lock_s, re.I):
                    result["passwords"][username] = "locked"
                elif len(trimmed) > len(username) + 1:
                    result["passwords"][username] = "unlocked"
                else:
                    result["passwords"][username] = "unknown"

        login_txt = _zip_read_text(zf, "login.txt")
        if login_txt:
            for line in login_txt.split("\n"):
                if not line.strip() or line.strip().startswith("#"):
                    continue
                m = _RE_LOGIN_DEF.match(line)
                if m:
                    result["loginDefs"][m.group(1)] = m.group(2)

        for pam_name in _PAM_FILENAMES:
            body = _zip_read_text(zf, pam_name)
            if body is not None:
                result["pamStack"][pam_name] = body

        meta_txt = _zip_read_text(zf, "MetaData.txt")
        if meta_txt:
            for line in meta_txt.split("\n"):
                ln = line.strip()
                if not ln or ln.startswith("Permissions;"):
                    continue
                parts = ln.split(";")
                if len(parts) >= 6:
                    result["metadataEntries"].append(
                        {
                            "mode": parts[0].strip(),
                            "path": parts[1].strip(),
                            "line": ln,
                        }
                    )

        last_txt = _zip_read_text(zf, "Lastlogininformation.txt")
        if last_txt:
            for line in last_txt.split("\n"):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    result["lastLogin"][parts[0]] = " ".join(parts[1:])

        rs = _zip_read_text(zf, "riskyServices.txt")
        if rs is not None:
            result["riskyServices"] = rs.strip()

        rh = _zip_read_text(zf, "rhosts.txt")
        if rh is not None:
            result["rhosts"] = rh.strip()

        sudo = _zip_read_text(zf, "Sudoers.txt")
        if sudo is not None:
            result["sudoers"] = sudo
        sudo_dir = _zip_read_text(zf, "SudoersDirectory.txt")
        if sudo_dir:
            result["sudoers"] = (
                (result["sudoers"] or "") + ("\n\n# --- SudoersDirectory.txt ---\n" if result.get("sudoers") else "")
                + sudo_dir
            )

    return result


def generate_findings(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    now = datetime.now()
    users: list[dict[str, Any]] = parsed.get("users") or []
    sshd: dict[str, str] = parsed.get("sshdConfig") or {}
    pwq: dict[str, Any] = parsed.get("passwordQuality") or {}
    fail: dict[str, Any] = parsed.get("faillockConfig") or {}
    passwords: dict[str, str] = parsed.get("passwords") or {}
    last_login: dict[str, str] = parsed.get("lastLogin") or {}

    password_records: list[dict[str, Any]] = list(parsed.get("passwordRecords") or [])
    login_defs: dict[str, str] = dict(parsed.get("loginDefs") or {})
    pam_stack: dict[str, str] = dict(parsed.get("pamStack") or {})
    metadata_entries: list[dict[str, Any]] = list(parsed.get("metadataEntries") or [])
    password_quality_present = bool(parsed.get("passwordQualityFilePresent"))
    user_by_name = {str(u["name"]): u for u in users if u.get("name") is not None}

    insecure_hash_users: list[str] = []
    empty_password_interactive: list[str] = []
    for rec in password_records:
        user = str(rec.get("user") or "")
        if not user:
            continue
        pst = str(rec.get("password_status") or "").strip().lower()
        lock = str(rec.get("lock_status") or "").strip().lower()
        if pst == "not secure":
            insecure_hash_users.append(user)
        if pst == "no password set" and lock != "locked":
            uo = user_by_name.get(user)
            sh = (uo or {}).get("shell") if uo else ""
            if _is_caat_interactive_shell(str(sh or "")):
                empty_password_interactive.append(user)

    findings.append(
        {
            "control": "Password hash strength (Passwordinformation.txt)",
            "status": "Non-compliant" if insecure_hash_users else "Compliant",
            "configuration": (
                "Accounts with PasswordStatus indicating a weak/not-approved hash: "
                + ", ".join(insecure_hash_users)
                if insecure_hash_users
                else "(none flagged as Not secure)"
            ),
            "detail": (
                "This control reads Passwordinformation.txt PasswordStatus for values such as “Not secure”, "
                "which indicate legacy or non-compliant password hashing. "
                "Expected standard: only modern approved hashes per policy (for example yescrypt/SHA-512). Observed: "
                + (
                    f"Users: {', '.join(insecure_hash_users)}."
                    if insecure_hash_users
                    else "No “Not secure” password status rows were parsed from the bundle."
                )
            ),
            "risk": "High" if insecure_hash_users else "Low",
            "recommendation": (
                "Force password reset with a compliant hashing algorithm and verify PAM/crypto policy."
                if insecure_hash_users
                else "Current configuration is acceptable."
            ),
        }
    )
    findings.append(
        {
            "control": "Interactive account with no password set",
            "status": "Non-compliant" if empty_password_interactive else "Compliant",
            "configuration": (
                ", ".join(empty_password_interactive)
                if empty_password_interactive
                else "(none: unlocked interactive with “No password set”)"
            ),
            "detail": (
                "This control flags interactive users (CAAT-style shell classification) whose Passwordinformation.txt "
                "row shows “No password set” while the account is not locked—high risk of unauthenticated access if misconfigured. "
                "Expected standard: no interactive account without a password or all such accounts locked. Observed: "
                + (
                    f"Users: {', '.join(empty_password_interactive)}."
                    if empty_password_interactive
                    else "No matching rows in the supplied Passwordinformation.txt."
                )
            ),
            "risk": "High" if empty_password_interactive else "Low",
            "recommendation": (
                "Lock the account, set a password, or remove the interactive shell unless formally approved."
                if empty_password_interactive
                else "Current configuration is acceptable."
            ),
        }
    )

    pass_max_status = "Compliant"
    pass_max_detail = (
        "This control reads login.txt (login.defs style) for PASS_MAX_DAYS. "
        f"Expected standard: PASS_MAX_DAYS ≤ {_PASS_MAX_DAYS_THRESHOLD} for this benchmark. Observed: "
    )
    pass_max_cfg = "(login.txt not in bundle)"
    if "PASS_MAX_DAYS" in login_defs:
        try:
            pmd = int(login_defs["PASS_MAX_DAYS"])
            pass_max_cfg = f"PASS_MAX_DAYS={pmd}"
            if pmd > _PASS_MAX_DAYS_THRESHOLD:
                pass_max_status = "Non-compliant"
            pass_max_detail += f"PASS_MAX_DAYS is set to {pmd}."
        except ValueError:
            pass_max_cfg = f"PASS_MAX_DAYS={login_defs['PASS_MAX_DAYS']!r} (unparseable)"
            pass_max_status = "Review"
            pass_max_detail += pass_max_cfg + "."
    else:
        pass_max_status = "Review"
        pass_max_detail += "PASS_MAX_DAYS not found in login.txt (file missing or directive absent)."
    findings.append(
        {
            "control": "login.defs PASS_MAX_DAYS",
            "status": pass_max_status,
            "configuration": pass_max_cfg,
            "detail": pass_max_detail,
            "risk": "Medium" if pass_max_status == "Non-compliant" else "Low",
            "recommendation": f"Set PASS_MAX_DAYS to {_PASS_MAX_DAYS_THRESHOLD} or less, aligned to corporate policy.",
        }
    )

    pass_min_status = "Compliant"
    pass_min_detail = (
        "This control reads login.txt for PASS_MIN_DAYS. "
        "Expected standard: PASS_MIN_DAYS at least 1 to discourage immediate password cycling attacks. Observed: "
    )
    pass_min_cfg = "(login.txt not in bundle)"
    if "PASS_MIN_DAYS" in login_defs:
        try:
            pmi = int(login_defs["PASS_MIN_DAYS"])
            pass_min_cfg = f"PASS_MIN_DAYS={pmi}"
            if pmi < 1:
                pass_min_status = "Non-compliant"
            pass_min_detail += f"PASS_MIN_DAYS is set to {pmi}."
        except ValueError:
            pass_min_cfg = f"PASS_MIN_DAYS={login_defs['PASS_MIN_DAYS']!r} (unparseable)"
            pass_min_status = "Review"
            pass_min_detail += pass_min_cfg + "."
    else:
        pass_min_status = "Review"
        pass_min_detail += "PASS_MIN_DAYS not found in login.txt (file missing or directive absent)."
    findings.append(
        {
            "control": "login.defs PASS_MIN_DAYS",
            "status": pass_min_status,
            "configuration": pass_min_cfg,
            "detail": pass_min_detail,
            "risk": "Low",
            "recommendation": "Set PASS_MIN_DAYS to at least 1 unless policy documents an exception.",
        }
    )

    pam_faillock_seen, pam_pwquality_seen, nullok_hits = _scan_pam_stack(pam_stack)
    if pam_stack:
        findings.append(
            {
                "control": "PAM nullok on password/auth",
                "status": "Non-compliant" if nullok_hits else "Compliant",
                "configuration": f"{len(nullok_hits)} line(s) in scanned PAM files" if nullok_hits else "(no nullok on pam_unix.so)",
                "detail": (
                    "This control scans collected PAM stack snippets for pam_unix.so lines containing nullok, "
                    "which can allow empty passwords where misconfigured. "
                    "Expected standard: no nullok on authentication/password stacks unless formally risk-accepted. Observed: "
                    + ("; ".join(nullok_hits[:12]) + (" …" if len(nullok_hits) > 12 else "") if nullok_hits else "No nullok matches in the scanned files.")
                ),
                "risk": "High" if nullok_hits else "Low",
                "recommendation": "Remove nullok unless explicitly approved with compensating controls.",
            }
        )
        findings.append(
            {
                "control": "PAM account lockout modules (faillock/tally)",
                "status": "Partially compliant" if not pam_faillock_seen else "Compliant",
                "configuration": ", ".join(sorted(pam_stack.keys())),
                "detail": (
                    "This control checks whether pam_faillock.so or pam_tally appears in the collected PAM configuration files. "
                    "Expected standard: account lockout is configured in the PAM stack consistent with policy. Observed: "
                    + (
                        "No pam_faillock.so / pam_tally lines found in the scanned files."
                        if not pam_faillock_seen
                        else "At least one lockout-related PAM module reference was found."
                    )
                ),
                "risk": "Medium",
                "recommendation": "Configure pam_faillock (or supported tally) with deny/unlock_time per policy.",
            }
        )
        findings.append(
            {
                "control": "PAM password-quality modules (pwquality/passwdqc/cracklib)",
                "status": "Partially compliant" if not pam_pwquality_seen else "Compliant",
                "configuration": ", ".join(sorted(pam_stack.keys())),
                "detail": (
                    "This control checks for pam_pwquality.so, pam_passwdqc.so, or pam_cracklib.so in collected PAM files. "
                    "Expected standard: password quality enforcement is present in the PAM password stack. Observed: "
                    + (
                        "No pam_pwquality/passwdqc/cracklib lines found in the scanned files."
                        if not pam_pwquality_seen
                        else "At least one password-quality PAM module reference was found."
                    )
                ),
                "risk": "Medium",
                "recommendation": "Configure pam_pwquality (or supported alternative) per password policy.",
            }
        )
    findings.append(
        {
            "control": "pwquality.conf evidence in bundle",
            "status": "Review" if not password_quality_present else "Compliant",
            "configuration": "passwordquality.txt present" if password_quality_present else "passwordquality.txt missing",
            "detail": (
                "This control only verifies that passwordquality.txt was collected in the audit bundle so pwquality.conf "
                "evidence can be reviewed (separate from PAM module checks). "
                "Expected standard: collector includes passwordquality.txt when pwquality is in scope. Observed: "
                + (
                    "passwordquality.txt is present."
                    if password_quality_present
                    else "passwordquality.txt was not found in the ZIP; pwquality settings could not be read from that file."
                )
            ),
            "risk": "Low",
            "recommendation": "Ensure the Linux audit script collects passwordquality.txt when assessing password quality.",
        }
    )

    minlen_early = int(pwq["minlen"]) if pwq.get("minlen") is not None else 0
    if password_quality_present and minlen_early > 0 and minlen_early < 12:
        findings.append(
            {
                "control": "pwquality minlen baseline (≥12)",
                "status": "Non-compliant",
                "configuration": f"minlen={minlen_early}",
                "detail": (
                    "This control applies a minimum baseline of 12 characters on minlen from passwordquality.txt "
                    "(softer than the separate “Password quality (pwquality)” benchmark that expects minlen ≥ 14). Observed: "
                    f"minlen is {minlen_early}."
                ),
                "risk": "Medium",
                "recommendation": "Increase minlen to at least 12, and preferably 14+ with enforce_for_root per policy.",
            }
        )

    meta_issues: list[str] = []
    seen_world: set[str] = set()
    for ent in metadata_entries:
        path = str(ent.get("path") or "")
        mode = _parse_octal_mode(ent.get("mode"))
        ev = str(ent.get("line") or "")
        if mode is None:
            continue
        if path == "/etc/passwd" and mode > _PASSWD_MAX_MODE:
            meta_issues.append(f"/etc/passwd mode {oct(mode)} exceeds {_PASSWD_MAX_MODE:o}")
        if path == "/etc/shadow" and mode > _SHADOW_MAX_MODE:
            meta_issues.append(f"/etc/shadow mode {oct(mode)} exceeds {_SHADOW_MAX_MODE:o}")
        if (mode & 0o002) and path.startswith(_SENSITIVE_PATH_PREFIXES) and path not in seen_world:
            seen_world.add(path)
            meta_issues.append(f"World-writable sensitive path: {path} ({oct(mode)})")
    findings.append(
        {
            "control": "Sensitive path permissions (MetaData.txt)",
            "status": "Non-compliant" if meta_issues else "Compliant",
            "configuration": " | ".join(meta_issues) if meta_issues else "(no MetaData.txt issues parsed)",
            "detail": (
                "This control parses MetaData.txt for weak /etc/passwd or /etc/shadow permissions and world-writable paths "
                "under sensitive prefixes (/bin, /sbin, /usr/bin, /usr/sbin, /etc, /var/spool/cron, /var/log, /root). "
                "Expected standard: modes within baseline; no world-writable sensitive paths. Observed: "
                + (
                    "; ".join(meta_issues)
                    if meta_issues
                    else "Either MetaData.txt was absent/empty or no failing rows were detected."
                )
            ),
            "risk": "High" if meta_issues else "Low",
            "recommendation": "Remediate permissions per hardening baseline; validate ownership and mount options.",
        }
    )

    shell_interactive_names = [
        u["name"]
        for u in users
        if u.get("shell") and u["shell"] not in _NON_INTERACTIVE_SHELLS
    ]

    permit_root = sshd.get("PermitRootLogin") or ""
    root_login_yes = permit_root.lower().startswith("yes")
    ssh_root_intro = (
        "This control checks whether SSH allows interactive login as the superuser account (root) "
        "over the network, which concentrates risk and complicates attribution. "
        "Expected standard: PermitRootLogin no (or prohibit-password only if policy explicitly allows "
        "key-based root and compensating controls), with day-to-day admin via named accounts and sudo. Observed: "
    )
    ssh_root_detail = ssh_root_intro + (
        f"PermitRootLogin is set to '{permit_root}'."
        if permit_root
        else "PermitRootLogin unset (implementation default is often prohibit-password; confirm against your sshd version)."
    )
    root_last_raw = last_login.get("root")
    if root_last_raw:
        root_parsed = parse_audit_last_login_timestamp(root_last_raw)
        if root_parsed:
            days_root = (now - root_parsed).days
            if 0 <= days_root <= 90:
                ssh_root_detail += f" Last-login data: recent root login noted ({root_last_raw.strip()})."
            elif days_root > 90:
                ssh_root_detail += (
                    f" Last-login data: last recorded root login ({root_last_raw.strip()}) is older than 90 days."
                )
        else:
            ssh_root_detail += (
                f" Last-login data: record present but date could not be parsed reliably: {root_last_raw.strip()}."
            )

    findings.append(
        {
            "control": "SSH root login",
            "status": "Non-compliant" if root_login_yes else "Compliant",
            "configuration": (
                f"PermitRootLogin={permit_root or '(unset)'}"
                + (f"; LastLogin(root)={root_last_raw.strip()}" if root_last_raw else "")
            ),
            "detail": ssh_root_detail,
            "risk": "High" if root_login_yes else "Low",
            "recommendation": (
                "Disable root SSH; use named accounts with sudo. Restrict via AllowUsers/Match, "
                "bastion-only source IPs, and key-only with break-glass procedure."
                if root_login_yes
                else "Current configuration is acceptable."
            ),
        }
    )

    password_auth = sshd.get("PasswordAuthentication") or ""
    password_auth_value = password_auth.lower()
    findings.append(
        {
            "control": "SSH password authentication",
            "status": "Compliant" if password_auth_value.startswith("no") else "Non-compliant",
            "configuration": f"PasswordAuthentication={password_auth or '(unset)'}",
            "detail": (
                "This control checks whether users may authenticate to SSH using passwords (subject to PAM and account lockout). "
                "Passwords are easier to brute-force or phish than keys. "
                "Expected standard: PasswordAuthentication no for internet-facing and production servers; "
                "use SSH keys (and MFA on a bastion where required). Observed: "
                + (
                    f"PasswordAuthentication is set to '{password_auth}'."
                    if password_auth
                    else "PasswordAuthentication unset (many builds default to yes)."
                )
            ),
            "risk": "Low" if password_auth_value.startswith("no") else "Medium",
            "recommendation": (
                "Current configuration is acceptable."
                if password_auth_value.startswith("no")
                else "Set PasswordAuthentication no; use key-based auth + MFA on bastion."
            ),
        }
    )

    minlen = int(pwq["minlen"]) if pwq.get("minlen") is not None else 0
    enforce_root = bool(pwq.get("enforce_for_root"))
    pw_quality_compliant = minlen >= 14 and enforce_root
    maxseq = pwq.get("maxsequence", "unset")
    findings.append(
        {
            "control": "Password quality (pwquality)",
            "status": "Compliant" if pw_quality_compliant else "Partially compliant",
            "configuration": (
                f"minlen={minlen or 'unset'}; maxsequence={maxseq}; "
                f"enforce_for_root={'yes' if enforce_root else 'no'}"
            ),
            "detail": (
                "This control checks Linux pwquality settings used when passwords are set or changed "
                "(minimum length, complexity credits, and whether root is subject to the same rules). "
                "Expected standard for this benchmark: minlen at least 14 and enforce_for_root enabled "
                "so root cannot bypass policy. Observed: "
                f"minlen={minlen or 'unset'}, maxsequence={maxseq}, enforce_for_root={'present' if enforce_root else 'missing'}."
            ),
            "risk": "Low",
            "recommendation": "Keep minlen ≥ 14; set explicit credit rules if policy requires.",
        }
    )

    deny = fail.get("deny")
    if deny is None:
        lockout_status = "Non-compliant"
    elif int(deny) <= 5:
        lockout_status = "Compliant"
    else:
        lockout_status = "Partially compliant"
    unlock_t = fail.get("unlock_time", "unset")
    findings.append(
        {
            "control": "Account lockout (faillock)",
            "status": lockout_status,
            "configuration": (
                f"deny={'(unset)' if deny is None else deny}; unlock_time={unlock_t}"
            ),
            "detail": (
                "This control checks faillock (PAM) settings that temporarily lock an account after repeated failed "
                "authentication attempts, slowing password guessing. "
                "Expected standard: deny set to a small number (here ≤5 failed attempts before lockout) and "
                "unlock_time defined so accounts recover automatically after a defined period. "
                "A missing deny means no attempt threshold is enforced. Observed: "
                + (
                    f"deny=unset (no lockout threshold configured); unlock_time={unlock_t}."
                    if deny is None
                    else f"deny={deny}, unlock_time={unlock_t}."
                )
            ),
            "risk": "Medium",
            "recommendation": "Set deny ≤ 5; set unlock_time; ensure audit.",
        }
    )

    risky = parsed.get("riskyServices") or ""
    findings.append(
        {
            "control": "Risky legacy services",
            "status": "Non-compliant" if risky else "Compliant",
            "configuration": risky if risky else "(none reported in riskyServices.txt)",
            "detail": (
                "This control checks for cleartext or weak legacy remote-access services (for example telnet, rsh, rexec) "
                "that should not run on hardened hosts. "
                "Expected standard: none of these services listening; remote administration only over SSH with modern "
                "ciphers and access controls. Observed: "
                + (f"Detected services: {risky}" if risky else "No risky services detected in the audit bundle.")
            ),
            "risk": "High" if risky else "Low",
            "recommendation": "Disable telnet/rsh/etc.; use SSH." if risky else "Current configuration is acceptable.",
        }
    )

    rhosts = parsed.get("rhosts") or ""
    findings.append(
        {
            "control": "rhosts trust files",
            "status": "Non-compliant" if rhosts else "Compliant",
            "configuration": rhosts if rhosts else "(none in rhosts.txt)",
            "detail": (
                "This control checks for ~/.rhosts (or equivalent) trust relationships used by legacy r-commands; "
                "they grant trust based on hostnames and are weak compared to SSH keys and proper identity. "
                "Expected standard: no .rhosts files present for users on the system. Observed: "
                + (f"Detected .rhosts files: {rhosts}" if rhosts else "No .rhosts files detected in the audit bundle.")
            ),
            "risk": "High" if rhosts else "Low",
            "recommendation": "Remove .rhosts; use SSH keys." if rhosts else "Current configuration is acceptable.",
        }
    )

    sudoers = parsed.get("sudoers") or ""
    nopasswd_lines: list[str] = []
    allall_lines: list[str] = []
    for line in sudoers.split("\n"):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if re.search(r"\bNOPASSWD\b", trimmed, re.I):
            nopasswd_lines.append(trimmed[:400])
        if re.search(r"\bALL\s*=\s*\(ALL\)\s*ALL\b", trimmed, re.I):
            allall_lines.append(trimmed[:400])
    findings.append(
        {
            "control": "Sudoers: NOPASSWD entries",
            "status": "Non-compliant / needs justification" if nopasswd_lines else "Compliant",
            "configuration": f"{len(nopasswd_lines)} matching line(s)" if nopasswd_lines else "(none)",
            "detail": (
                "This control scans Sudoers.txt (and SudoersDirectory.txt when bundled) for NOPASSWD, which allows "
                "command execution without re-authentication unless tightly scoped. "
                "Expected standard: no NOPASSWD except formally approved, time-bound, and logged exceptions. Observed: "
                + (
                    "; ".join(nopasswd_lines[:8]) + (" …" if len(nopasswd_lines) > 8 else "")
                    if nopasswd_lines
                    else "No NOPASSWD matches in the supplied sudoers text."
                )
            ),
            "risk": "High" if nopasswd_lines else "Low",
            "recommendation": (
                "Remove NOPASSWD or replace with scoped command aliases and MFA/session recording where required."
                if nopasswd_lines
                else "Current configuration is acceptable."
            ),
        }
    )
    findings.append(
        {
            "control": "Sudoers: unrestricted ALL=(ALL) ALL",
            "status": "Non-compliant / needs justification" if allall_lines else "Compliant",
            "configuration": f"{len(allall_lines)} matching line(s)" if allall_lines else "(none)",
            "detail": (
                "This control flags unrestricted sudo rules of the form ALL=(ALL) ALL for any user—including the "
                "postgres OS account when present—which grant full root-equivalent access. "
                "Expected standard: least-privilege sudo with command groups and change control. Observed: "
                + (
                    "; ".join(allall_lines[:8]) + (" …" if len(allall_lines) > 8 else "")
                    if allall_lines
                    else "No ALL=(ALL) ALL matches in the supplied sudoers text."
                )
            ),
            "risk": "High" if allall_lines else "Low",
            "recommendation": (
                "Replace with scoped command aliases; remove broad ALL rules unless formally risk-accepted."
                if allall_lines
                else "Current configuration is acceptable."
            ),
        }
    )

    interactive_users = [
        u["name"]
        for u in users
        if u.get("shell") and u["shell"] not in _NON_INTERACTIVE_SHELLS
        and u["name"] not in ("sync", "shutdown", "halt")
    ]
    findings.append(
        {
            "control": "Local users with interactive shells",
            "status": "Review",
            "configuration": (
                ", ".join(interactive_users)
                if interactive_users
                else "(no interactive users after exclusions)"
            ),
            "detail": (
                "This control inventories local passwd entries whose login shell is interactive (not nologin/false), "
                "meaning the account can obtain a normal login session. "
                "Expected standard: only approved human or break-glass accounts; service and application accounts "
                "should use non-interactive shells. Observed: "
                + (
                    f"Interactive local users: {', '.join(interactive_users)}."
                    if interactive_users
                    else "No interactive local users found (after excluding sync/shutdown/halt)."
                )
            ),
            "risk": "Medium",
            "recommendation": "Validate approvals; disable where not needed; centralize auth.",
        }
    )

    empty_passwords = sshd.get("PermitEmptyPasswords") or ""
    empty_yes = empty_passwords.lower().startswith("yes")
    findings.append(
        {
            "control": "PermitEmptyPasswords",
            "status": "Non-compliant" if empty_yes else "Compliant",
            "configuration": f"PermitEmptyPasswords={empty_passwords or '(unset)'}",
            "detail": (
                "This control checks sshd PermitEmptyPasswords, which allows login when the account has an empty "
                "password hash—dangerous if any such account exists. "
                "Expected standard: PermitEmptyPasswords no everywhere. Observed: "
                + (
                    f"PermitEmptyPasswords is set to '{empty_passwords}'."
                    if empty_passwords
                    else "PermitEmptyPasswords unset (sshd default is typically no)."
                )
            ),
            "risk": "High" if empty_yes else "Low",
            "recommendation": (
                "Set PermitEmptyPasswords no; audit for empty hashes."
                if empty_yes
                else "Current configuration is acceptable."
            ),
        }
    )

    pubkey = sshd.get("PubkeyAuthentication") or ""
    pubkey_v = pubkey.lower()
    if pubkey_v.startswith("yes"):
        pk_status = "Compliant"
    elif pubkey_v.startswith("no"):
        pk_status = "Non-compliant"
    else:
        pk_status = "Review"
    findings.append(
        {
            "control": "PubkeyAuthentication",
            "status": pk_status,
            "configuration": f"PubkeyAuthentication={pubkey or '(unset)'}",
            "detail": (
                "This control checks whether SSH public-key authentication is enabled so users can authenticate "
                "with cryptographic keys instead of passwords alone. "
                "Expected standard: PubkeyAuthentication yes (often paired with PasswordAuthentication no on servers). Observed: "
                + (
                    f"PubkeyAuthentication is set to '{pubkey}'."
                    if pubkey
                    else "PubkeyAuthentication unset (depends on sshd defaults and distribution)."
                )
            ),
            "risk": "Low" if pubkey_v.startswith("yes") else "Medium",
            "recommendation": "Enable pubkey; pair with PasswordAuthentication no.",
        }
    )

    max_auth = _safe_int(sshd.get("MaxAuthTries"))
    max_auth_status = "Review"
    if max_auth is not None:
        max_auth_status = "Compliant" if max_auth <= 4 else "Partially compliant"
    findings.append(
        {
            "control": "MaxAuthTries",
            "status": max_auth_status,
            "configuration": f"MaxAuthTries={max_auth if max_auth is not None else '(unset)'}",
            "detail": (
                "This control limits how many authentication attempts are allowed per SSH connection before disconnect, "
                "which reduces online password guessing. "
                "Expected standard: MaxAuthTries explicitly set to a low value (this benchmark treats ≤4 as compliant). Observed: "
                + (
                    f"MaxAuthTries is set to {max_auth}."
                    if max_auth is not None
                    else "MaxAuthTries unset (sshd uses its built-in default; confirm in documentation)."
                )
            ),
            "risk": "Medium",
            "recommendation": "Set MaxAuthTries 3–4.",
        }
    )

    max_sess = _safe_int(sshd.get("MaxSessions"))
    max_sess_status = "Review"
    if max_sess is not None:
        max_sess_status = "Compliant" if max_sess <= 10 else "Partially compliant"
    findings.append(
        {
            "control": "MaxSessions",
            "status": max_sess_status,
            "configuration": f"MaxSessions={max_sess if max_sess is not None else '(unset)'}",
            "detail": (
                "This control caps concurrent multiplexed sessions per SSH connection, limiting resource abuse and session sprawl. "
                "Expected standard: MaxSessions set to a modest limit aligned with policy (this benchmark treats ≤10 as compliant). Observed: "
                + (
                    f"MaxSessions is set to {max_sess}."
                    if max_sess is not None
                    else "MaxSessions unset (sshd default applies)."
                )
            ),
            "risk": "Low",
            "recommendation": "Cap per policy (often 10).",
        }
    )

    alive_i = _safe_int(sshd.get("ClientAliveInterval"))
    alive_c = _safe_int(sshd.get("ClientAliveCountMax"))
    alive_status = "Review"
    if alive_i is not None and alive_c is not None:
        timeout = alive_i * alive_c
        alive_status = "Compliant" if timeout <= 900 else "Partially compliant"
    findings.append(
        {
            "control": "ClientAliveInterval / ClientAliveCountMax",
            "status": alive_status,
            "configuration": (
                f"ClientAliveInterval={alive_i if alive_i is not None else '(unset)'}; "
                f"ClientAliveCountMax={alive_c if alive_c is not None else '(unset)'}; "
                + (
                    f"effective_idle_timeout_s={alive_i * alive_c}"
                    if alive_i is not None and alive_c is not None
                    else "effective_idle_timeout_s=(n/a)"
                )
            ),
            "detail": (
                "These settings send keepalive messages so idle SSH sessions are detected and closed, reducing abandoned "
                "authenticated sessions and stale tunnels. "
                "Expected standard: both set so the product Interval×CountMax does not exceed about 15 minutes (900s) "
                "for this benchmark. Observed: "
                + (
                    f"Interval={alive_i}s, CountMax={alive_c}, effective idle-timeout={alive_i * alive_c}s."
                    if alive_i is not None and alive_c is not None
                    else f"Interval={alive_i or 'unset'}, CountMax={alive_c or 'unset'}."
                )
            ),
            "risk": "Low",
            "recommendation": "Set e.g., ClientAliveInterval 300 & ClientAliveCountMax 3.",
        }
    )

    grace = _safe_int(sshd.get("LoginGraceTime"))
    grace_status = "Review"
    if grace is not None:
        grace_status = "Compliant" if grace <= 60 else "Partially compliant"
    findings.append(
        {
            "control": "LoginGraceTime",
            "status": grace_status,
            "configuration": f"LoginGraceTime={grace if grace is not None else '(unset)'} (seconds)",
            "detail": (
                "This control sets how long sshd waits for a user to complete authentication after connecting; "
                "shorter windows reduce time for slow brute-force attempts. "
                "Expected standard: LoginGraceTime between about 30 and 60 seconds unless policy specifies otherwise. Observed: "
                + (
                    f"LoginGraceTime is set to {grace} seconds."
                    if grace is not None
                    else "LoginGraceTime unset (sshd default applies)."
                )
            ),
            "risk": "Low",
            "recommendation": "Set 30–60 seconds.",
        }
    )

    tcp = sshd.get("AllowTcpForwarding") or ""
    tcp_v = tcp.lower()
    findings.append(
        {
            "control": "AllowTcpForwarding",
            "status": "Compliant" if tcp_v == "no" else "Review",
            "configuration": f"AllowTcpForwarding={tcp or '(unset)'}",
            "detail": (
                "This control governs whether SSH may be used as a TCP tunnel/forward (local/remote forwarding), "
                "which can bypass perimeter controls if misused. "
                "Expected standard: AllowTcpForwarding no on servers unless a documented need exists; if needed, restrict with Match blocks. Observed: "
                + (
                    f"AllowTcpForwarding is set to '{tcp}'."
                    if tcp
                    else "AllowTcpForwarding unset (sshd default may allow limited forwarding; verify version)."
                )
            ),
            "risk": "Low",
            "recommendation": "Disable unless required; if required, scope via Match blocks.",
        }
    )

    x11 = sshd.get("X11Forwarding") or ""
    x11_v = x11.lower()
    if x11_v == "yes":
        x11_status = "Non-compliant"
    elif x11_v == "no":
        x11_status = "Compliant"
    else:
        x11_status = "Review"
    findings.append(
        {
            "control": "X11Forwarding",
            "status": x11_status,
            "configuration": f"X11Forwarding={x11 or '(unset)'}",
            "detail": (
                "This control checks whether SSH can forward X11 GUI traffic; on typical servers it enlarges attack surface without benefit. "
                "Expected standard: X11Forwarding no on servers; enable only on dedicated jump or desktop hosts if required. Observed: "
                + (
                    f"X11Forwarding is set to '{x11}'."
                    if x11
                    else "X11Forwarding unset (default varies by platform and sshd version)."
                )
            ),
            "risk": "Medium" if x11_v == "yes" else "Low",
            "recommendation": "Set X11Forwarding no for servers.",
        }
    )

    hb = sshd.get("HostbasedAuthentication") or ""
    hb_v = hb.lower()
    findings.append(
        {
            "control": "HostbasedAuthentication",
            "status": "Non-compliant" if hb_v.startswith("yes") else "Compliant",
            "configuration": f"HostbasedAuthentication={hb or '(unset)'}",
            "detail": (
                "This control checks host-based (.rhosts-style) SSH authentication, which trusts remote host identity "
                "rather than per-user keys and is generally unsuitable for modern environments. "
                "Expected standard: HostbasedAuthentication no. Observed: "
                + (
                    f"HostbasedAuthentication is set to '{hb}'."
                    if hb
                    else "HostbasedAuthentication unset (sshd default is typically no)."
                )
            ),
            "risk": "High" if hb_v.startswith("yes") else "Low",
            "recommendation": (
                "Prefer key-based user auth; disable hostbased."
                if hb_v.startswith("yes")
                else "Current configuration is acceptable."
            ),
        }
    )

    uid0 = [u["name"] for u in users if u.get("uid") == 0 and u.get("name") != "root"]
    findings.append(
        {
            "control": "UID 0 accounts (non-root)",
            "status": "Non-compliant" if uid0 else "Compliant",
            "configuration": (
                f"UID 0 accounts (non-root): {', '.join(uid0)}" if uid0 else "Only root has UID=0"
            ),
            "detail": (
                "This control checks for any login name other than root that shares UID 0 (superuser). "
                "Multiple UID-0 accounts break accountability and can hide privileged access. "
                "Expected standard: only the root account uses UID 0; other privilege use is via sudo with logging. Observed: "
                + (
                    f"Accounts with UID 0 besides root: {', '.join(uid0)}."
                    if uid0
                    else "Only root has UID 0 in Userinformation.txt."
                )
            ),
            "risk": "High" if uid0 else "Low",
            "recommendation": "Remove UID 0; use sudo with audit." if uid0 else "Current configuration is acceptable.",
        }
    )

    uid_map: dict[int, list[str]] = {}
    for u in users:
        uid_map.setdefault(int(u["uid"]), []).append(u["name"])
    duplicates = [(uid, names) for uid, names in uid_map.items() if len(names) > 1]
    findings.append(
        {
            "control": "Duplicate UIDs",
            "status": "Non-compliant" if duplicates else "Compliant",
            "configuration": (
                "; ".join(f"UID {uid}: {', '.join(names)}" for uid, names in duplicates)
                if duplicates
                else "(no duplicate UIDs)"
            ),
            "detail": (
                "This control verifies that each numeric UID maps to at most one login name in /etc/passwd. "
                "Duplicate UIDs break file ownership semantics and auditing. "
                "Expected standard: every UID appears once; duplicates are remediated with a planned UID change and filesystem ownership fix. Observed: "
                + (
                    "; ".join(f"UID {uid}: {', '.join(names)}" for uid, names in duplicates)
                    if duplicates
                    else "All UIDs are unique in Userinformation.txt."
                )
            ),
            "risk": "High" if duplicates else "Low",
            "recommendation": (
                "Assign unique UIDs; reconcile ownerships." if duplicates else "Current configuration is acceptable."
            ),
        }
    )

    sys_shells = [
        u["name"]
        for u in users
        if int(u.get("uid") or 0) < 1000
        and u.get("shell")
        and u["shell"] not in _NON_INTERACTIVE_SHELLS
    ]
    findings.append(
        {
            "control": "System accounts with interactive shells",
            "status": "Non-compliant" if sys_shells else "Compliant",
            "configuration": (
                f"UID<1000 with interactive shell: {', '.join(sys_shells)}"
                if sys_shells
                else "(none)"
            ),
            "detail": (
                "This control checks low-UID system accounts (UID < 1000 here) that still have an interactive login shell. "
                "Such accounts are often targets for lateral movement if compromised. "
                "Expected standard: system accounts use /usr/sbin/nologin or /bin/false unless an extremely rare documented exception exists. Observed: "
                + (
                    f"System accounts with interactive shells: {', '.join(sys_shells)}."
                    if sys_shells
                    else "No system accounts (UID < 1000) have interactive shells."
                )
            ),
            "risk": "Medium" if sys_shells else "Low",
            "recommendation": (
                "Set shell to /usr/sbin/nologin or /bin/false." if sys_shells else "Current configuration is acceptable."
            ),
        }
    )

    unlocked_interactive = [
        n
        for n in shell_interactive_names
        if passwords.get(n) in ("unlocked", None)
    ]
    unknown_pwd = [n for n in shell_interactive_names if passwords.get(n) == "unknown"]
    unlocked_detail = (
        "This control compares interactive local users (from passwd) with Passwordinformation.txt to see whether "
        "accounts are locked at the OS password store. "
        "Expected standard: only approved interactive users remain unlocked; others locked or managed via central IdM. Observed: "
    )
    if unlocked_interactive:
        unlocked_detail += f"Unlocked interactive users: {', '.join(unlocked_interactive)}."
    if unknown_pwd:
        unlocked_detail += (
            (" " if unlocked_interactive else "")
            + f"Password state unknown (parse failed or insufficient line): {', '.join(unknown_pwd)}."
        )
    if not unlocked_interactive and not unknown_pwd:
        unlocked_detail += "All interactive accounts are locked or not listed in Passwordinformation.txt."

    findings.append(
        {
            "control": "Unlocked local accounts",
            "status": (
                "Review" if (unlocked_interactive or unknown_pwd) else "Compliant"
            ),
            "configuration": (
                f"Unlocked: {', '.join(unlocked_interactive) if unlocked_interactive else '(none)'}; "
                f"Password_unknown: {', '.join(unknown_pwd) if unknown_pwd else '(none)'}"
            ),
            "detail": unlocked_detail.strip(),
            "risk": "Medium" if (unlocked_interactive or unknown_pwd) else "Low",
            "recommendation": "Verify business need; lock or migrate to central auth.",
        }
    )

    dormant_users: list[str] = []
    unknown_date: list[str] = []
    never_logged_in: list[str] = []
    for name in shell_interactive_names:
        if name == "root":
            continue
        last_str = last_login.get(name)
        if not last_str:
            continue
        raw = last_str.strip()
        if "**Never logged in**" in raw or "never logged in" in raw.lower():
            never_logged_in.append(name)
            continue
        login_dt = parse_audit_last_login_timestamp(last_str)
        if not login_dt:
            unknown_date.append(f"{name} (raw: {raw})")
            continue
        days_since = (now - login_dt).days
        if days_since >= _STALE_ACCOUNT_DAYS:
            dormant_users.append(f"{name} ({days_since} days since last parsed login)")

    if dormant_users or unknown_date or never_logged_in or last_login:
        dormant_detail = (
            f"This control uses last-login strings for interactive users (excluding root) to flag long inactivity "
            f"(≥{_STALE_ACCOUNT_DAYS} days when the timestamp parses reliably), accounts with no last-login row in the bundle, "
            "or “never logged in” markers—aligned with common CAAT stale-account logic. "
            "Expected standard: dormant or unused accounts disabled or removed; unknown last-login data corrected at source. Observed: "
        )
        if dormant_users:
            dormant_detail += f"Stale (≥{_STALE_ACCOUNT_DAYS}d, parsed): {', '.join(dormant_users)}."
        if never_logged_in:
            dormant_detail += (
                (" " if dormant_users else "")
                + f"No usable last-login record or never logged in: {', '.join(never_logged_in)}."
            )
        if unknown_date:
            dormant_detail += (
                (" " if (dormant_users or never_logged_in) else "")
                + f"Last login date unknown (skipped ambiguous/unparseable): {'; '.join(unknown_date)}."
            )
        if not dormant_users and not unknown_date and not never_logged_in:
            dormant_detail += (
                "No stale, never-logged-in, or unparseable last-login rows were found among interactive users "
                "with the supplied Lastlogininformation.txt."
            )

        cfg_parts: list[str] = []
        if dormant_users:
            cfg_parts.append(f"Stale≥{_STALE_ACCOUNT_DAYS}d: " + ", ".join(dormant_users))
        if never_logged_in:
            cfg_parts.append("Never/no last-login: " + ", ".join(never_logged_in))
        if unknown_date:
            cfg_parts.append("Unparseable: " + "; ".join(unknown_date))
        dormant_configuration = " | ".join(cfg_parts) if cfg_parts else (
            "(last-login data present; no stale, never-logged-in, or unparseable rows for scoped interactive users)"
        )
        findings.append(
            {
                "control": f"Dormant or stale interactive accounts (≥{_STALE_ACCOUNT_DAYS}d / never logged in)",
                "status": "Review",
                "configuration": dormant_configuration,
                "detail": dormant_detail.strip(),
                "risk": "Low",
                "recommendation": "Disable or remove unused accounts; reconcile last-login collection for unknown rows.",
            }
        )

    return findings


def generate_exceptions(
    findings: list[dict[str, Any]], summary: dict[str, Any]
) -> list[dict[str, Any]]:
    scope = summary.get("hostname") or "This host"
    exceptions: list[dict[str, Any]] = []
    trigger_status = frozenset(
        {"Non-compliant", "Non-compliant / needs justification", "Review"}
    )

    for finding in findings:
        if finding.get("status") not in trigger_status:
            continue
        exc: dict[str, Any] | None = None
        ctrl = finding.get("control")
        st = finding.get("status")

        if ctrl == "SSH root login" and st == "Non-compliant":
            exc = {
                "exception": "Root SSH enabled",
                "scope": scope,
                "reason": "Break-glass for on-call DBAs during incidents.",
                "controls": "Bastion IP restriction; key-only; MFA on bastion; session recording; sudo/root logs to SIEM; monthly review.",
                "expiry": "Temporary – 90 days; review monthly.",
            }
        elif ctrl == "SSH password authentication" and st == "Non-compliant":
            exc = {
                "exception": "SSH password authentication enabled",
                "scope": scope,
                "reason": "Legacy automation/support tooling.",
                "controls": "Bastion-only; pwquality minlen 14; faillock deny=5; migrate to key-based.",
                "expiry": "Temporary – 60 days.",
            }
        elif ctrl == "Sudoers: NOPASSWD entries" and st == "Non-compliant / needs justification":
            exc = {
                "exception": "sudo NOPASSWD rules present",
                "scope": scope,
                "reason": "Automation or operator convenience.",
                "controls": "Command allow-lists; remove NOPASSWD where feasible; change ticket; session logging.",
                "expiry": "Temporary – 60 days.",
            }
        elif ctrl == "Sudoers: unrestricted ALL=(ALL) ALL" and st == "Non-compliant / needs justification":
            exc = {
                "exception": "Unrestricted sudo ALL=(ALL) ALL",
                "scope": scope,
                "reason": "Vendor/DBA full privilege requirement.",
                "controls": "Command aliases; peer review; time-bound; SIEM on sudo logs.",
                "expiry": "Temporary – 60 days.",
            }
        elif ctrl == "Password hash strength (Passwordinformation.txt)" and st == "Non-compliant":
            exc = {
                "exception": "Weak or legacy password hash reported",
                "scope": scope,
                "reason": "Legacy accounts or incomplete migration.",
                "controls": "Forced password reset; verify PAM/crypto; inventory affected users.",
                "expiry": "Temporary – 30 days.",
            }
        elif ctrl == "Interactive account with no password set" and st == "Non-compliant":
            exc = {
                "exception": "Interactive account without password",
                "scope": scope,
                "reason": "Provisioning or break-glass workflow.",
                "controls": "Lock or set password; remove interactive shell if service account.",
                "expiry": "Temporary – 7 days.",
            }
        elif ctrl == "login.defs PASS_MAX_DAYS" and st == "Non-compliant":
            exc = {
                "exception": "PASS_MAX_DAYS above policy threshold",
                "scope": scope,
                "reason": "Legacy password-aging policy.",
                "controls": f"Reduce PASS_MAX_DAYS to ≤{_PASS_MAX_DAYS_THRESHOLD}; communicate to users.",
                "expiry": "Temporary – 90 days.",
            }
        elif ctrl == "login.defs PASS_MIN_DAYS" and st == "Non-compliant":
            exc = {
                "exception": "PASS_MIN_DAYS below minimum",
                "scope": scope,
                "reason": "Legacy login.defs template.",
                "controls": "Set PASS_MIN_DAYS ≥ 1; validate against auth policy.",
                "expiry": "Temporary – 90 days.",
            }
        elif ctrl == "PAM nullok on password/auth" and st == "Non-compliant":
            exc = {
                "exception": "PAM nullok configured",
                "scope": scope,
                "reason": "Legacy PAM stack compatibility.",
                "controls": "Remove nullok; test auth flows; document compensating controls if retained.",
                "expiry": "Temporary – 30 days.",
            }
        elif ctrl == "PAM account lockout modules (faillock/tally)" and st == "Partially compliant":
            exc = {
                "exception": "PAM lockout modules not seen in collected files",
                "scope": scope,
                "reason": "Collector subset or alternate lockout mechanism.",
                "controls": "Verify pam_faillock in live stack; expand collection if needed.",
                "expiry": "Temporary – 90 days.",
            }
        elif ctrl == "PAM password-quality modules (pwquality/passwdqc/cracklib)" and st == "Partially compliant":
            exc = {
                "exception": "PAM password-quality modules not seen in collected files",
                "scope": scope,
                "reason": "Alternate module names or out-of-band enforcement.",
                "controls": "Validate live PAM password stack; align evidence collection.",
                "expiry": "Temporary – 90 days.",
            }
        elif ctrl == "pwquality minlen baseline (≥12)" and st == "Non-compliant":
            exc = {
                "exception": "pwquality minlen below 12",
                "scope": scope,
                "reason": "Legacy pwquality.conf.",
                "controls": "Raise minlen; pair with enforce_for_root per policy.",
                "expiry": "Temporary – 60 days.",
            }
        elif ctrl == "Sensitive path permissions (MetaData.txt)" and st == "Non-compliant":
            exc = {
                "exception": "Weak permissions on sensitive paths (MetaData.txt)",
                "scope": scope,
                "reason": "Packaging or ad-hoc chmod.",
                "controls": "Restore baseline modes; FIM on critical paths; change ticket.",
                "expiry": "Temporary – 30 days.",
            }
        elif (ctrl or "").startswith("Dormant or stale interactive accounts") and st == "Review":
            exc = {
                "exception": "Stale or never-logged-in interactive accounts",
                "scope": scope,
                "reason": "Seasonal or shared human accounts.",
                "controls": "Account review; disable unused; fix last-login reporting.",
                "expiry": "Temporary – 90 days.",
            }
        elif ctrl == "UID 0 accounts (non-root)" and st == "Non-compliant":
            exc = {
                "exception": "UID 0 accounts (non-root)",
                "scope": scope,
                "reason": "Legacy startup tooling.",
                "controls": "Maintenance-window only; service isolation; FIM on /etc/passwd; SIEM alert on UID 0 logins; change ticket.",
                "expiry": "Temporary – 30 days.",
            }
        elif ctrl == "Duplicate UIDs" and st == "Non-compliant":
            exc = {
                "exception": "Duplicate UIDs",
                "scope": scope,
                "reason": "Pending UID reallocation.",
                "controls": "Ownership reconciliation plan; change window; SIEM correlation for impacted UIDs.",
                "expiry": "Temporary – 30 days.",
            }
        elif ctrl == "System accounts with interactive shells" and st == "Non-compliant":
            exc = {
                "exception": "System accounts with shells",
                "scope": scope,
                "reason": "Short-term operational access.",
                "controls": "IP restriction; command allow-list; session recording; scheduled removal.",
                "expiry": "Temporary – 30–60 days.",
            }
        elif ctrl in ("AllowTcpForwarding", "X11Forwarding") and st != "Compliant":
            exc = {
                "exception": (
                    "X11 forwarding enabled" if ctrl == "X11Forwarding" else "TCP forwarding allowed"
                ),
                "scope": scope,
                "reason": "Vendor tooling/tunnels.",
                "controls": "Match scoping by user/IP, limited ports, time-bound changes, logging to SIEM.",
                "expiry": "Temporary – 60 days.",
            }

        if exc is not None:
            exceptions.append(exc)

    if not exceptions:
        exceptions.append(
            {
                "exception": "No exceptions required",
                "scope": scope,
                "reason": "Current configuration meets policy for reviewed controls.",
                "controls": "Continue SIEM monitoring; quarterly review.",
                "expiry": "12 months.",
            }
        )

    return exceptions


def run_linux_audit_zip(data: bytes) -> dict[str, Any]:
    """Parse ZIP, return summary, findings, and exceptions (JSON-serializable)."""
    parsed = parse_audit_zip(data)
    summary = parsed.get("summary") or {}
    findings = generate_findings(parsed)
    exceptions = generate_exceptions(findings, summary)
    return {"summary": summary, "findings": findings, "exceptions": exceptions}
