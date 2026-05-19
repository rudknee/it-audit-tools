"""Views for Database Review Tools (ported from Flask)."""

import io
import uuid
import zipfile
from pathlib import Path, PurePath

import pandas as pd
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.models import ReviewRunLog
from audit.oracle_processing import process_oracle_uploads
from audit.review_logging import (
    log_oracle_review_failure,
    log_oracle_review_success,
    log_sql_review_failure,
    log_sql_review_success,
)

from linux_audit_engine import run_linux_audit_zip

from audit.upload_validation import upload_rules_json, validate_upload_filename
from sql_auth_exceptions import (
    build_exceptions_summary,
    generate_exceptions_register,
    load_and_normalize,
    validate_required_columns,
)

ALLOWED_DOWNLOAD_FILES = frozenset(
    {
        'SQL_Authorisation_Exceptions_Combined.csv',
        'SQL_Authorisation_Exceptions_Summary_By_Environment.csv',
    }
)


def landing(request):
    return render(request, 'landing.html')


def review_log(request):
    """Front-end page listing stored review run history."""
    qs = ReviewRunLog.objects.all()
    review_type = request.GET.get('type', '').strip()
    status = request.GET.get('status', '').strip()
    query = request.GET.get('q', '').strip()

    if review_type in {ReviewRunLog.REVIEW_SQL, ReviewRunLog.REVIEW_ORACLE}:
        qs = qs.filter(review_type=review_type)
    if status in {ReviewRunLog.STATUS_SUCCESS, ReviewRunLog.STATUS_FAILED}:
        qs = qs.filter(status=status)
    if query:
        filters = (
            Q(systems__icontains=query)
            | Q(source_filenames__icontains=query)
            | Q(error_message__icontains=query)
        )
        try:
            filters |= Q(session_id=uuid.UUID(query))
        except ValueError:
            if len(query) >= 8:
                filters |= Q(session_id__icontains=query)
        qs = qs.filter(filters)

    paginator = Paginator(qs, 25)
    page_number = request.GET.get('page', '1')
    page_obj = paginator.get_page(page_number)

    stats = ReviewRunLog.objects.aggregate(
        total=Count('id'),
        success=Count('id', filter=Q(status=ReviewRunLog.STATUS_SUCCESS)),
        failed=Count('id', filter=Q(status=ReviewRunLog.STATUS_FAILED)),
        sql_count=Count('id', filter=Q(review_type=ReviewRunLog.REVIEW_SQL)),
        oracle_count=Count('id', filter=Q(review_type=ReviewRunLog.REVIEW_ORACLE)),
    )

    return render(
        request,
        'review_log.html',
        {
            'page_obj': page_obj,
            'stats': stats,
            'filter_type': review_type,
            'filter_status': status,
            'filter_query': query,
        },
    )


def sql_audit(request):
    return render(
        request,
        'index.html',
        {'upload_rules_json': upload_rules_json('csv')},
    )


def oracle_audit(request):
    return render(
        request,
        'oracle_audit.html',
        {'upload_rules_json': upload_rules_json('zip')},
    )


@require_http_methods(['POST'])
def oracle_audit_process(request):
    """Accept one or more Oracle audit ZIPs with system labels; return combined JSON."""
    started_at = timezone.now()
    run_session_id = str(uuid.uuid4())
    files = request.FILES.getlist('files[]')
    env_labels = request.POST.getlist('env_labels[]')
    filenames: list[str] = []

    def _fail(message: str, status: int = 400) -> JsonResponse:
        log_oracle_review_failure(
            request=request,
            started_at=started_at,
            session_id=run_session_id,
            filename=', '.join(filenames),
            error_message=message,
        )
        return JsonResponse({'error': message}, status=status)

    valid_entries = []
    for idx, uploaded in enumerate(files):
        if not uploaded or not uploaded.name:
            continue
        ok, err = validate_upload_filename(uploaded.name, 'zip')
        if not ok:
            return _fail(f'"{uploaded.name}": {err}')
        env = 'default'
        if idx < len(env_labels):
            env = (env_labels[idx] or 'default').strip() or 'default'
        filenames.append(PurePath(uploaded.name).name)
        valid_entries.append((uploaded, env))

    if not valid_entries:
        return _fail('Please upload at least one .zip file.')

    for idx, (_, env) in enumerate(valid_entries):
        if not env or env == 'default':
            return _fail(f'Please select a system for file {idx + 1}.')

    try:
        payload = process_oracle_uploads(valid_entries)
        environments = [env for _, env in valid_entries]
        log_oracle_review_success(
            request=request,
            started_at=started_at,
            session_id=run_session_id,
            filenames=filenames,
            environments=environments,
            payload=payload,
        )
        return JsonResponse(payload)
    except zipfile.BadZipFile:
        return _fail('Invalid or corrupted ZIP file.')
    except ValueError as e:
        return _fail(str(e))
    except Exception as e:
        return _fail(str(e), status=500)


@require_http_methods(['GET', 'POST'])
def upload_file(request):
    if request.method == 'GET':
        return redirect('audit:sql_audit')

    files = request.FILES.getlist('files[]')
    env_labels = request.POST.getlist('env_labels[]')
    apply_iapply_filter = request.POST.get('apply_iapply_filter', 'false').lower() == 'true'
    date_format = request.POST.get('date_format', 'DMY')

    valid_entries = []
    for idx, f in enumerate(files):
        if f and f.name:
            ok, err = validate_upload_filename(f.name, 'csv')
            if not ok:
                messages.error(request, f'"{f.name}": {err}')
                return redirect('audit:sql_audit')
            env = 'default'
            if idx < len(env_labels):
                env = (env_labels[idx] or 'default').strip() or 'default'
            valid_entries.append((f, env))

    if not valid_entries:
        messages.error(request, 'No file selected')
        return redirect('audit:sql_audit')

    session_id = str(uuid.uuid4())
    started_at = timezone.now()
    upload_root = settings.UPLOAD_FOLDER
    output_root = settings.OUTPUT_FOLDER
    source_filenames = [PurePath(f.name).name for f, _ in valid_entries]

    try:
        output_dir = output_root / session_id
        output_dir.mkdir(exist_ok=True)

        combined_detailed = []
        environments = []
        total_rows_processed = 0
        filter_applied_in_session = apply_iapply_filter

        for file_obj, env_label in valid_entries:
            safe_name = PurePath(file_obj.name).name
            if not safe_name:
                continue
            upload_path = upload_root / f'{session_id}_{safe_name}'
            with open(upload_path, 'wb+') as dest:
                for chunk in file_obj.chunks():
                    dest.write(chunk)

            df = load_and_normalize(str(upload_path), date_format)
            validate_required_columns(df)
            total_rows_processed += len(df)

            use_iapply_filter = apply_iapply_filter or env_label == 'iApply'
            if use_iapply_filter:
                filter_applied_in_session = True

            detailed_df, _summary_df = generate_exceptions_register(
                df, env_label, use_iapply_filter
            )
            if len(detailed_df) > 0:
                combined_detailed.append(detailed_df)
            environments.append(env_label)

            upload_path.unlink(missing_ok=True)

        if combined_detailed:
            detailed_all = pd.concat(combined_detailed, ignore_index=True)
        else:
            detailed_all = pd.DataFrame()

        if len(detailed_all) > 0:
            summary_by_env = build_exceptions_summary(
                detailed_all, by_environment=True
            ).sort_values(['Environment', 'Exception'])
            total_records = len(detailed_all)
        else:
            summary_by_env = pd.DataFrame(
                columns=['Environment', 'Exception', 'Description', 'Count', 'AffectedAccounts']
            )
            total_records = 0

        detailed_file = output_dir / 'SQL_Authorisation_Exceptions_Combined.csv'
        summary_file = output_dir / 'SQL_Authorisation_Exceptions_Summary_By_Environment.csv'
        detailed_all.to_csv(detailed_file, index=False)
        summary_by_env.to_csv(summary_file, index=False)

        summary_data = summary_by_env.to_dict('records')
        unique_envs = sorted(set(environments))

        log_sql_review_success(
            request=request,
            started_at=started_at,
            session_id=session_id,
            environments=environments,
            filenames=source_filenames,
            total_rows=total_rows_processed,
            exception_records=total_records,
            iapply_filter_applied=filter_applied_in_session,
            date_format=date_format,
        )

        return render(
            request,
            'results.html',
            {
                'session_id': session_id,
                'env_label': ', '.join(unique_envs),
                'summary_data': summary_data,
                'total_records': total_records,
                'total_rows': total_rows_processed,
                'apply_iapply_filter': filter_applied_in_session,
                'environments': unique_envs,
            },
        )

    except Exception as e:
        try:
            for p in upload_root.glob(f'{session_id}_*'):
                p.unlink(missing_ok=True)
        except OSError:
            pass
        log_sql_review_failure(
            request=request,
            started_at=started_at,
            session_id=session_id,
            filenames=source_filenames,
            environments=[env for _, env in valid_entries],
            error_message=str(e),
            date_format=date_format,
            iapply_filter_applied=apply_iapply_filter,
        )
        messages.error(request, f'Error processing file: {e}')
        return redirect('audit:sql_audit')


def download_file(request, session_id, filename):
    if filename not in ALLOWED_DOWNLOAD_FILES:
        raise Http404('Invalid file')

    file_path = settings.OUTPUT_FOLDER / str(session_id) / filename
    if not file_path.is_file():
        messages.error(request, 'File not found')
        return redirect('audit:sql_audit')

    response = FileResponse(
        open(file_path, 'rb'),
        as_attachment=True,
        filename=filename,
    )
    return response
