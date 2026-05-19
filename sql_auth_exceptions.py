#!/usr/bin/env python3
"""
SQL Server Authorisation Analysis - Exceptions Register Generator

This tool ingests CSV output from IT-Audit-Tools_MSSQL_Script_v3.10 and produces
an exceptions register with detailed findings and summary statistics.

Exception categories:
    E1  SQL logins without password policy enforced.
    E2  SQL logins without password expiration configured.
    E3  Active logins with passwords older than 365 days.
    E4  Powerful server roles / permissions (e.g. sysadmin, CONTROL SERVER).
    E5  Membership in the db_owner database role.
    E6  Direct object-level grants to users (not via standard roles).
    E7  Orphaned database users with no matching login.
    E8  Disabled accounts that still retain powerful access.

Usage:
    python sql_auth_exceptions.py \\
      --input /path/to/caat.csv \\
      --output-dir /path/to/out \\
      --env-label axale3 \\
      [--apply-iapply-filter true|false] \\
      [--date-format DMY|MDY|YMD] \\
      [--verbose]

Optional ``--apply-iapply-filter`` excludes iApply-style SQL logins from E1–E3.
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Iterable, Optional, List, Tuple
from datetime import datetime, timedelta

import pandas as pd
from pandas import DataFrame, NaT

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Utility Functions
# ============================================================================

def _is_null_like(series: pd.Series) -> pd.Series:
    """Check if values in a Series are null, empty, or 'NULL'."""
    return series.apply(
        lambda x: pd.isna(x) or str(x).strip() == '' or str(x).upper() == 'NULL'
    )


def normalize_string(value: str) -> str:
    """Normalize string: strip whitespace and convert to uppercase."""
    if pd.isna(value) or value == "NULL" or value == "":
        return ""
    return str(value).strip().upper()


def parse_date_flexible(date_str: str) -> Optional[datetime]:
    """
    Parse date string trying multiple formats.
    
    Tries formats in order:
    - %d-%m-%y %H:%M
    - %d-%m-%Y %H:%M
    - %Y-%m-%d %H:%M
    - %d/%m/%Y %H:%M
    - Date-only variants of above
    """
    if pd.isna(date_str) or date_str == "NULL" or date_str == "":
        return None
    
    date_str = str(date_str).strip()
    if not date_str:
        return None
    
    formats = [
        '%d-%m-%y %H:%M',
        '%d-%m-%Y %H:%M',
        '%Y-%m-%d %H:%M',
        '%d/%m/%Y %H:%M',
        '%d-%m-%y',
        '%d-%m-%Y',
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%m-%d-%Y %H:%M',
        '%m/%d/%Y %H:%M',
        '%m-%d-%Y',
        '%m/%d/%Y',
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except (ValueError, TypeError):
            continue
    
    logger.warning(f"Could not parse date: {date_str}")
    return None


def load_and_normalize(csv_path: str, date_hint: str = "DMY") -> DataFrame:
    """
    Load CSV from IT-Audit-Tools_MSSQL_Script_v3.10 format.
    
    Expected format:
    - Row 0: metadata (ignored)
    - Row 1: column headers
    - Row 2+: data
    
    Args:
        csv_path: Path to input CSV file
        date_hint: Hint for date format (DMY/MDY/YMD), not strictly enforced
        
    Returns:
        Normalized DataFrame with cleaned column names and normalized fields
    """
    logger.info(f"Loading CSV from: {csv_path}")
    
    # Read CSV without headers initially
    df = pd.read_csv(csv_path, header=None, low_memory=False)
    
    if len(df) < 2:
        raise ValueError(f"CSV must have at least 2 rows (metadata + headers). Found {len(df)} rows.")
    
    # Set headers from row 1 (index 1), drop rows 0-1 (metadata + headers)
    df.columns = df.iloc[1].astype(str)
    df = df.iloc[2:].copy()
    df.reset_index(drop=True, inplace=True)
    
    # Strip whitespace from column names
    df.columns = [str(col).strip() for col in df.columns]
    
    logger.info(f"Loaded {len(df)} data rows with {len(df.columns)} columns")
    
    # Normalize specific fields to uppercase
    fields_to_normalize = [
        'Logintype',
        'Disabled',
        'Password policy enforced?',
        'Password expiration?'
    ]
    
    for field in fields_to_normalize:
        if field in df.columns:
            df[field] = df[field].apply(normalize_string)
    
    # Parse date fields
    date_fields = [
        'Last password set',
        'DbPermissionCreated',
        'DbPermissionModified',
        'SrvAuthCreatedDate',
        'SrvAuthModDate'
    ]
    
    for field in date_fields:
        if field in df.columns:
            df[field] = df[field].apply(parse_date_flexible)
    
    # Replace empty strings, "NULL", and NaN with None for consistency
    df = df.replace(['NULL', ''], None)
    
    return df


def validate_required_columns(df: DataFrame) -> None:
    """Validate that required columns are present in the DataFrame."""
    required_columns = [
        'Login',
        'Logintype',
        'Disabled',
        'Password policy enforced?',
        'Password expiration?',
        'Last password set',
        'SrvAuth',
        'SrvAuthType',
        'SrvAuthStatus',
        'DbAuth',
        'DbAuthType',
        'MappedDBUser',
        'Database'
    ]
    
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(missing)}\n"
            f"Available columns: {', '.join(df.columns)}"
        )


_AFFECTED_ACCOUNTS_DISPLAY_MAX = 10
_AFFECTED_ACCOUNTS_TRUNCATED_MSG = "Full list in the CSV download."

# Brief explanations keyed by exception code prefix (E1. … E8.)
EXCEPTION_DESCRIPTIONS: dict[str, str] = {
    "E1.": (
        "SQL authentication logins that are not required to follow password policy "
        "(complexity, history, and related rules)."
    ),
    "E2.": (
        "SQL logins configured so passwords never expire, which increases risk if credentials are compromised."
    ),
    "E3.": (
        "Enabled accounts whose password has not been changed within the allowed period "
        "(default: older than 365 days)."
    ),
    "E4.": (
        "Accounts with powerful server roles or permissions (for example sysadmin or CONTROL SERVER) "
        "that can fully administer the SQL Server instance."
    ),
    "E5.": (
        "Database users who are members of db_owner and therefore have full control within that database."
    ),
    "E6.": (
        "Permissions granted directly on database objects to users, rather than through standard database roles."
    ),
    "E7.": (
        "Database users that have no matching server login—often left behind after a login was removed."
    ),
    "E8.": (
        "Disabled logins that still hold powerful server or database privileges and should be reviewed for cleanup."
    ),
}


def exception_description(exception_type: str) -> str:
    """Return a brief explanation for an ExceptionType label."""
    if not exception_type or pd.isna(exception_type):
        return ""
    label = str(exception_type).strip()
    for prefix, text in EXCEPTION_DESCRIPTIONS.items():
        if label.startswith(prefix):
            return text
    return ""


def account_label_from_row(row: pd.Series) -> Optional[str]:
    """Login name for an exception row; falls back to MappedDBUser (e.g. orphaned DB users)."""
    login = row.get("Login")
    if pd.notna(login):
        login_s = str(login).strip()
        if login_s and login_s.upper() != "NULL":
            return login_s
    mapped = row.get("MappedDBUser")
    if pd.notna(mapped):
        mapped_s = str(mapped).strip()
        if mapped_s and mapped_s.upper() != "NULL":
            return mapped_s
    return None


def format_affected_accounts_display(
    accounts: Iterable[str],
    max_show: int = _AFFECTED_ACCOUNTS_DISPLAY_MAX,
) -> str:
    """Comma-separated account list for summary UI/CSV; truncates with CSV download note when > max_show."""
    unique = sorted({str(a).strip() for a in accounts if a and str(a).strip()})
    if not unique:
        return "—"
    if len(unique) <= max_show:
        return ", ".join(unique)
    shown = ", ".join(unique[:max_show])
    return f"{shown} … ({len(unique)} accounts; {_AFFECTED_ACCOUNTS_TRUNCATED_MSG})"


def build_exceptions_summary(
    detailed_df: DataFrame,
    *,
    by_environment: bool = False,
) -> DataFrame:
    """
    Build summary with Count (unique accounts), Description, and AffectedAccounts per exception.

    Count matches the number of distinct logins/users in Affected accounts, not the number
    of detailed CSV rows (one account may appear on multiple rows for different grants).
    """
    base_cols = ["Exception", "Description", "Count", "AffectedAccounts"]
    if by_environment:
        empty_cols = ["Environment"] + base_cols
    else:
        empty_cols = base_cols

    if detailed_df.empty:
        return pd.DataFrame(columns=empty_cols)

    work = detailed_df.copy()
    work["_Account"] = work.apply(account_label_from_row, axis=1)
    group_cols = ["Environment", "ExceptionType"] if by_environment else ["ExceptionType"]

    summary = (
        work.groupby(group_cols, dropna=False)
        .agg(
            Count=(
                "_Account",
                lambda s: int(s.dropna().nunique()),
            ),
            AffectedAccounts=(
                "_Account",
                lambda s: format_affected_accounts_display(s.dropna().unique().tolist()),
            ),
        )
        .reset_index()
    )
    summary = summary.rename(columns={"ExceptionType": "Exception"})
    summary.insert(
        summary.columns.get_loc("Exception") + 1,
        "Description",
        summary["Exception"].map(exception_description),
    )
    return summary


def apply_iapply_exclusion(df: DataFrame, pattern: str = r'^[A-Z]{2}[0-9]{4}$') -> DataFrame:
    """
    Filter out logins matching the iApply exclusion pattern.

    Args:
        df: DataFrame to filter
        pattern: Regex pattern to match (default: ^[A-Z]{2}[0-9]{4}$)

    Returns:
        Filtered DataFrame excluding matching logins
    """
    if 'Login' not in df.columns:
        return df
    
    regex = re.compile(pattern)
    mask = df['Login'].apply(
        lambda x: not (pd.notna(x) and regex.match(str(x).strip()))
    )
    return df[mask].copy()


# ============================================================================
# Exception Detection Functions
# ============================================================================

def detect_sql_no_password_policy(df: DataFrame) -> DataFrame:
    """
    E1: SQL logins without password policy enforced.
    
    Criteria:
    - Logintype == "SQL_LOGIN"
    - Password policy enforced? == "No"
    - Disabled != "Yes"
    """
    mask = (
        (df['Logintype'] == 'SQL_LOGIN') &
        (df['Password policy enforced?'] == 'NO') &
        (df['Disabled'] != 'YES')
    )
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E1. SQL logins without password policy'
    return result


def detect_sql_no_password_expiration(df: DataFrame) -> DataFrame:
    """
    E2: SQL logins without password expiration.
    
    Criteria:
    - Logintype == "SQL_LOGIN"
    - Password expiration? == "No"
    - Disabled != "Yes"
    """
    mask = (
        (df['Logintype'] == 'SQL_LOGIN') &
        (df['Password expiration?'] == 'NO') &
        (df['Disabled'] != 'YES')
    )
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E2. SQL logins without password expiration'
    return result


def detect_password_older_than(df: DataFrame, days: int = 365) -> DataFrame:
    """
    E3: Active logins with password older than specified days.
    
    Criteria:
    - Disabled != "Yes"
    - Last password set is not null/parsable
    - Last password set < (today - days)
    """
    today = datetime.now()
    cutoff_date = today - timedelta(days=days)
    
    # Filter for non-disabled accounts
    mask_disabled = (df['Disabled'] != 'YES')
    
    # Filter for non-null password dates
    mask_date = df['Last password set'].notna()
    
    # Filter for dates older than cutoff
    mask_old = df['Last password set'].apply(
        lambda x: x is not None and x < cutoff_date if pd.notna(x) else False
    )
    
    mask = mask_disabled & mask_date & mask_old
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = f'E3. Active logins with password older than {days} days'
    return result


def detect_powerful_server_roles(df: DataFrame) -> DataFrame:
    """
    E4: Powerful server roles / permissions.
    
    Criteria:
    - SrvAuth IN powerful roles: sysadmin, serveradmin, securityadmin, setupadmin,
      processadmin, diskadmin, bulkadmin
    - OR SrvAuth CONTAINS powerful permissions: CONTROL SERVER, ALTER ANY LOGIN,
      IMPERSONATE ANY LOGIN, ALTER SERVER STATE
    """
    powerful_roles = {
        'sysadmin', 'serveradmin', 'securityadmin', 'setupadmin',
        'processadmin', 'diskadmin', 'bulkadmin'
    }
    
    powerful_permissions = [
        'CONTROL SERVER',
        'ALTER ANY LOGIN',
        'IMPERSONATE ANY LOGIN',
        'ALTER SERVER STATE'
    ]
    
    # Check for role membership (case-insensitive)
    mask_roles = df['SrvAuth'].apply(
        lambda x: str(x).upper() in {r.upper() for r in powerful_roles}
        if pd.notna(x) else False
    )
    
    # Check for permission strings (case-insensitive)
    mask_perms = df['SrvAuth'].apply(
        lambda x: any(perm.upper() in str(x).upper() for perm in powerful_permissions)
        if pd.notna(x) else False
    )
    
    mask = mask_roles | mask_perms
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E4. Powerful server roles / permissions'
    return result


def detect_db_owner_membership(df: DataFrame) -> DataFrame:
    """
    E5: db_owner role membership.
    
    Criteria:
    - DbAuth == "db_owner"
    """
    mask = df['DbAuth'].apply(
        lambda x: str(x).upper() == 'DB_OWNER' if pd.notna(x) else False
    )
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E5. db_owner role membership'
    return result


def detect_direct_object_grants(df: DataFrame) -> DataFrame:
    """
    E6: Direct object-level grants to users.
    
    Criteria:
    - DbAuthType contains "OBJECT" OR DBPermissionHasEffectOnName is not null
    - AND MappedDBUser (lowercase) NOT IN excluded roles
    """
    excluded_roles = {
        'db_owner', 'db_accessadmin', 'db_securityadmin', 'db_ddladmin',
        'db_backupoperator', 'db_datareader', 'db_datawriter', 'db_denydatareader',
        'db_denydatawriter', 'dbmanager', 'loginmanager', 'dbm_monitor', 'public'
    }
    
    # Check for object-level grants
    mask_object_type = df['DbAuthType'].apply(
        lambda x: 'OBJECT' in str(x).upper() if pd.notna(x) else False
    )
    
    mask_has_effect = df['DBPermissionHasEffectOnName'].notna()
    
    mask_object_grant = mask_object_type | mask_has_effect
    
    # Exclude standard roles
    mask_not_excluded = df['MappedDBUser'].apply(
        lambda x: str(x).lower() not in excluded_roles if pd.notna(x) else False
    )
    
    mask = mask_object_grant & mask_not_excluded
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E6. Direct object-level grants to users'
    return result


def detect_orphaned_users(df: DataFrame) -> DataFrame:
    """
    E7: Orphaned database users (MappedDBUser present but Login null/empty).
    
    Collapse to one row per (Database, MappedDBUser) to avoid CAAT join inflation.
    
    Criteria:
    - MappedDBUser is not null/empty
    - Login is null or empty
    """
    user_present = ~_is_null_like(df["MappedDBUser"])
    login_missing = _is_null_like(df["Login"])
    
    out = df.loc[user_present & login_missing].copy()
    
    # De-duplicate by user per database (ignore varying grants/objects)
    out = out.drop_duplicates(subset=["Database", "MappedDBUser"], keep="first")
    
    if len(out) > 0:
        out["ExceptionType"] = "E7. Orphaned database users (no matching login)"
    return out


def detect_disabled_with_powerful_access(df: DataFrame) -> DataFrame:
    """
    E8: Disabled accounts with powerful access.
    
    Criteria:
    - Disabled == "Yes"
    - AND (DbAuth == "db_owner" OR SrvAuth in powerful roles/permissions from E4)
    """
    mask_disabled = (df['Disabled'] == 'YES')
    
    # Check db_owner
    mask_db_owner = df['DbAuth'].apply(
        lambda x: str(x).upper() == 'DB_OWNER' if pd.notna(x) else False
    )
    
    # Check powerful server roles (reuse E4 logic)
    powerful_roles = {
        'sysadmin', 'serveradmin', 'securityadmin', 'setupadmin',
        'processadmin', 'diskadmin', 'bulkadmin'
    }
    
    powerful_permissions = [
        'CONTROL SERVER',
        'ALTER ANY LOGIN',
        'IMPERSONATE ANY LOGIN',
        'ALTER SERVER STATE'
    ]
    
    mask_roles = df['SrvAuth'].apply(
        lambda x: str(x).upper() in {r.upper() for r in powerful_roles}
        if pd.notna(x) else False
    )
    
    mask_perms = df['SrvAuth'].apply(
        lambda x: any(perm.upper() in str(x).upper() for perm in powerful_permissions)
        if pd.notna(x) else False
    )
    
    mask_powerful = mask_db_owner | mask_roles | mask_perms
    mask = mask_disabled & mask_powerful
    
    result = df[mask].copy()
    if len(result) > 0:
        result['ExceptionType'] = 'E8. Disabled accounts with powerful access'
    return result


# ============================================================================
# Main Processing Logic
# ============================================================================

def generate_exceptions_register(
    df: DataFrame,
    env_label: str,
    apply_iapply_filter: bool = False
) -> Tuple[DataFrame, DataFrame]:
    """
    Generate exceptions register from normalized DataFrame.
    
    Args:
        df: Normalized input DataFrame
        env_label: Environment label for output files
        apply_iapply_filter: Whether to apply iApply login exclusion to E1–E3
        
    Returns:
        Tuple of (detailed_exceptions_df, summary_df)
    """
    logger.info("Starting exception detection...")
    
    # Run all exception detectors
    exceptions = []
    
    # E1: SQL logins without password policy
    e1 = detect_sql_no_password_policy(df)
    if apply_iapply_filter:
        e1 = apply_iapply_exclusion(e1)
    exceptions.append(e1)
    
    # E2: SQL logins without password expiration
    e2 = detect_sql_no_password_expiration(df)
    if apply_iapply_filter:
        e2 = apply_iapply_exclusion(e2)
    exceptions.append(e2)
    
    # E3: Active logins with password older than 365 days
    e3 = detect_password_older_than(df, days=365)
    if apply_iapply_filter:
        e3 = apply_iapply_exclusion(e3)
    exceptions.append(e3)
    
    # E4: Powerful server roles / permissions
    e4 = detect_powerful_server_roles(df)
    exceptions.append(e4)
    
    # E5: db_owner role membership
    e5 = detect_db_owner_membership(df)
    exceptions.append(e5)
    
    # E6: Direct object-level grants to users
    e6 = detect_direct_object_grants(df)
    exceptions.append(e6)
    
    # E7: Orphaned database users
    e7 = detect_orphaned_users(df)
    exceptions.append(e7)
    
    # E8: Disabled accounts with powerful access
    e8 = detect_disabled_with_powerful_access(df)
    exceptions.append(e8)
    
    # Combine all exceptions
    detailed_df = pd.concat([e for e in exceptions if len(e) > 0], ignore_index=True)
    
    # Optional deduplication on a sensible subset of keys to avoid
    # inflating counts with identical grants while preserving distinct grants.
    if len(detailed_df) > 0:
        dedupe_keys = [
            'ExceptionType',
            'Login',
            'MappedDBUser',
            'Database',
            'SrvAuth',
            'DbAuth',
        ]
        existing_keys = [k for k in dedupe_keys if k in detailed_df.columns]
        if existing_keys:
            detailed_df = detailed_df.drop_duplicates(subset=existing_keys, keep='first')
    
    # Add Environment column and reorder columns according to spec
    if len(detailed_df) > 0:
        detailed_df.insert(0, 'Environment', env_label)
        detailed_df.insert(
            2,
            'Description',
            detailed_df['ExceptionType'].map(exception_description),
        )

        # Define preferred column order (spec order + any remaining columns)
        preferred_order = [
            'Environment', 'ExceptionType', 'Description', 'Login', 'Logintype', 'Disabled',
            'Password policy enforced?', 'Password expiration?', 'Last password set',
            'SrvAuth', 'SrvAuthType', 'SrvAuthStatus',
            'DbAuth', 'DbAuthType', 'DBPermissionHasEffectOnName',
            'MappedDBUser', 'Database'
        ]
        
        # Get columns that exist in the DataFrame
        existing_preferred = [col for col in preferred_order if col in detailed_df.columns]
        remaining_cols = [col for col in detailed_df.columns if col not in existing_preferred]
        
        # Reorder columns
        detailed_df = detailed_df[existing_preferred + remaining_cols]
    
    summary_df = build_exceptions_summary(detailed_df, by_environment=False)
    
    logger.info(f"Detected {len(detailed_df)} exception records across {len(summary_df)} categories")
    
    return detailed_df, summary_df


def write_outputs(
    detailed_df: DataFrame,
    summary_df: DataFrame,
    output_dir: str,
    env_label: str
) -> None:
    """Write detailed exceptions and summary CSVs to output directory."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Write detailed exceptions CSV
    detailed_file = output_path / f"SQL_Authorisation_Exceptions_{env_label}.csv"
    detailed_df.to_csv(detailed_file, index=False)
    logger.info(f"Written detailed exceptions to: {detailed_file}")
    
    # Write summary CSV
    summary_file = output_path / f"SQL_Authorisation_Exceptions_Summary_{env_label}.csv"
    summary_df.to_csv(summary_file, index=False)
    logger.info(f"Written summary to: {summary_file}")


def print_summary(summary_df: DataFrame) -> None:
    """Print a readable summary to stdout."""
    print("\n" + "=" * 70)
    print("SQL AUTHORISATION EXCEPTIONS SUMMARY")
    print("=" * 70)
    
    if len(summary_df) == 0:
        print("No exceptions detected.")
    else:
        total = summary_df['Count'].sum()
        print(f"\nTotal exception records: {total}\n")
        for _, row in summary_df.iterrows():
            accounts = row.get("AffectedAccounts", "—")
            desc = row.get("Description", "")
            print(f"{row['Exception']}")
            if desc:
                print(f"  {desc}")
            print(f"  Count: {row['Count']}")
            print(f"  Affected accounts: {accounts}\n")
        print(f"TOTAL records: {total}")
    
    print("=" * 70 + "\n")


# ============================================================================
# CLI Entry Point
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate SQL Server authorisation exceptions register from CAAT CSV output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--self-test',
        action='store_true',
        help='Run self-test with minimal fixture data'
    )
    
    parser.add_argument(
        '--input',
        required=False,
        help='Path to input CAAT CSV file'
    )
    
    parser.add_argument(
        '--output-dir',
        required=False,
        help='Directory to write output CSV files'
    )
    
    parser.add_argument(
        '--env-label',
        required=False,
        help='Environment/system label (e.g., axale, iApply, axale3)'
    )
    
    parser.add_argument(
        '--apply-iapply-filter',
        type=str,
        default='false',
        choices=['true', 'false', 'True', 'False'],
        help='Apply iApply login exclusion to E1–E3 (default: false)'
    )
    
    parser.add_argument(
        '--date-format',
        type=str,
        default='DMY',
        choices=['DMY', 'MDY', 'YMD'],
        help='Date format hint (default: DMY)'
    )
    
    parser.add_argument (
        '--verbose',
        action='store_true',
        help='Enable INFO-level logging'
    )
    
    args = parser.parse_args()
    
    # Validate required arguments (unless self-test)
    if not args.self_test:
        if not args.input:
            parser.error('--input is required (unless using --self-test)')
        if not args.output_dir:
            parser.error('--output-dir is required (unless using --self-test)')
        if not args.env_label:
            parser.error('--env-label is required (unless using --self-test)')
    
    return args


def run_self_test() -> None:
    """Run self-test with minimal fixture data."""
    print("Running self-test...")
    
    # Create minimal test data
    test_data = {
        'Login': ['test_login', 'AH6534', 'user1', 'user2', None, 'user3', None],
        'Logintype': ['SQL_LOGIN', 'SQL_LOGIN', 'SQL_LOGIN', 'WINDOWS_LOGIN', 'SQL_LOGIN', 'SQL_LOGIN', 'SQL_LOGIN'],
        'Disabled': ['No', 'No', 'No', 'No', 'No', 'Yes', 'No'],
        'Password policy enforced?': ['No', 'No', 'Yes', 'No', 'No', 'No', 'No'],
        'Password expiration?': ['No', 'Yes', 'Yes', 'No', 'No', 'No', 'No'],
        'Last password set': [
            datetime.now() - timedelta(days=400),
            datetime.now() - timedelta(days=100),
            datetime.now() - timedelta(days=50),
            None,
            None,
            None,
            None
        ],
        'SrvAuth': ['sysadmin', 'public', 'serveradmin', None, None, 'securityadmin', None],
        'SrvAuthType': ['SERVER', 'SERVER', 'SERVER', None, None, 'SERVER', None],
        'SrvAuthStatus': ['GRANT', 'GRANT', 'GRANT', None, None, 'GRANT', None],
        'DbAuth': ['db_owner', 'public', None, None, None, 'db_owner', None],
        'DbAuthType': ['ROLE', 'ROLE', None, None, None, 'ROLE', None],
        'DBPermissionHasEffectOnName': [None, None, 'table1', None, None, None, None],
        'MappedDBUser': ['user1', 'user2', 'user3', 'orphan', None, 'user4', 'orphan_user'],
        'Database': ['db1', 'db1', 'db2', 'db3', 'db4', 'db5', 'db6']
    }
    
    df = pd.DataFrame(test_data)
    
    # Normalize
    df['Logintype'] = df['Logintype'].apply(normalize_string)
    df['Disabled'] = df['Disabled'].apply(normalize_string)
    df['Password policy enforced?'] = df['Password policy enforced?'].apply(normalize_string)
    df['Password expiration?'] = df['Password expiration?'].apply(normalize_string)
    
    # Test exceptions
    e1 = detect_sql_no_password_policy(df)
    e1_filtered = apply_iapply_exclusion(e1)
    
    e2 = detect_sql_no_password_expiration(df)
    e3 = detect_password_older_than(df, days=365)
    e4 = detect_powerful_server_roles(df)
    e5 = detect_db_owner_membership(df)
    e6 = detect_direct_object_grants(df)
    e7 = detect_orphaned_users(df)
    e8 = detect_disabled_with_powerful_access(df)
    
    # Assertions
    assert len(e1) == 4, f"E1: Expected 4, got {len(e1)}"
    assert len(e1_filtered) == 3, f"E1 filtered: Expected 3, got {len(e1_filtered)}"
    assert len(e2) == 3, f"E2: Expected 3, got {len(e2)}"
    assert len(e3) == 1, f"E3: Expected 1, got {len(e3)}"
    assert len(e4) == 3, f"E4: Expected 3, got {len(e4)}"
    assert len(e5) == 2, f"E5: Expected 2, got {len(e5)}"
    assert len(e6) == 1, f"E6: Expected 1, got {len(e6)}"
    assert len(e7) == 1, f"E7: Expected 1, got {len(e7)}"
    assert len(e8) == 1, f"E8: Expected 1, got {len(e8)}"
    
    print("✓ All self-tests passed!")


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
    
    # Handle self-test
    if args.self_test:
        try:
            run_self_test()
            return 0
        except AssertionError as e:
            logger.error(f"Self-test failed: {e}")
            return 1
    
    # Validate input file
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        return 1
    
    # Process
    try:
        logger.info("=" * 70)
        logger.info("SQL AUTHORISATION EXCEPTIONS REGISTER GENERATOR")
        logger.info("=" * 70)
        logger.info(f"Input: {input_path}")
        logger.info(f"Output directory: {args.output_dir}")
        logger.info(f"Environment label: {args.env_label}")
        logger.info(f"Apply iApply exclusion filter: {args.apply_iapply_filter}")
        logger.info("=" * 70)
        
        # Load and normalize
        df = load_and_normalize(str(input_path), args.date_format)
        logger.info(f"Loaded {len(df)} records")
        
        # Validate required columns
        validate_required_columns(df)
        
        # Generate exceptions
        apply_filter = args.apply_iapply_filter.lower() == 'true'
        detailed_df, summary_df = generate_exceptions_register(
            df, args.env_label, apply_filter
        )
        
        # Write outputs
        write_outputs(detailed_df, summary_df, args.output_dir, args.env_label)
        
        # Print summary
        print_summary(summary_df)
        
        logger.info("=" * 70)
        logger.info("Processing completed successfully")
        logger.info("=" * 70)
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())

