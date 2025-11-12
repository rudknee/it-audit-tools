#!/usr/bin/env python3
"""
SQL Server Authorisation Analysis - Web Application

Flask web application for generating SQL Server authorisation exceptions register
from CAAT CSV output files.
"""

import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import pandas as pd

from sql_auth_exceptions import (
    load_and_normalize,
    validate_required_columns,
    generate_exceptions_register
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'

# Ensure directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
Path(app.config['OUTPUT_FOLDER']).mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {'csv'}


def allowed_file(filename):
    """Check if file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render the main upload page."""
    return render_template('index.html')


@app.route('/linux-audit')
def linux_audit():
    """Render the Linux audit review page."""
    return render_template('linux_audit.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and processing (supports multiple files)."""
    # Gather files and environment labels as lists
    files = request.files.getlist('files[]')
    env_labels = request.form.getlist('env_labels[]')
    apply_axale2_filter = request.form.get('apply_axale2_filter', 'false').lower() == 'true'
    date_format = request.form.get('date_format', 'DMY')

    # Validate presence
    valid_entries = []
    for idx, f in enumerate(files):
        if f and f.filename:
            if not allowed_file(f.filename):
                flash(f'Invalid file type for "{f.filename}". Please upload CSV.', 'error')
                return redirect(url_for('index'))
            # Match env label by index; fallback default
            env = 'default'
            if idx < len(env_labels):
                env = (env_labels[idx] or 'default').strip() or 'default'
            valid_entries.append((f, env))

    if not valid_entries:
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    # Generate unique session ID for this upload batch
    session_id = str(uuid.uuid4())
    
    try:
        # Prepare output directory
        output_dir = Path(app.config['OUTPUT_FOLDER']) / session_id
        output_dir.mkdir(exist_ok=True)

        # Accumulators
        combined_detailed = []
        environments = []
        total_rows_processed = 0

        # Persist each upload temporarily, process, then delete
        for (file_obj, env_label) in valid_entries:
            filename = secure_filename(file_obj.filename)
            upload_path = Path(app.config['UPLOAD_FOLDER']) / f"{session_id}_{filename}"
            file_obj.save(str(upload_path))

            df = load_and_normalize(str(upload_path), date_format)
            validate_required_columns(df)
            total_rows_processed += len(df)

            detailed_df, _summary_df = generate_exceptions_register(
                df, env_label, apply_axale2_filter
            )
            if len(detailed_df) > 0:
                combined_detailed.append(detailed_df)
            environments.append(env_label)

            # cleanup
            upload_path.unlink(missing_ok=True)

        # Combine detailed across environments
        if combined_detailed:
            detailed_all = pd.concat(combined_detailed, ignore_index=True)
        else:
            detailed_all = pd.DataFrame()

        # Build summary per environment
        if len(detailed_all) > 0:
            summary_by_env = (
                detailed_all.groupby(['Environment', 'ExceptionType'])
                .size()
                .reset_index(name='Count')
                .rename(columns={'ExceptionType': 'Exception'})
                .sort_values(['Environment', 'Exception'])
            )
            total_records = int(summary_by_env['Count'].sum())
        else:
            summary_by_env = pd.DataFrame(columns=['Environment', 'Exception', 'Count'])
            total_records = 0

        # Save combined outputs
        detailed_file = output_dir / "SQL_Authorisation_Exceptions_Combined.csv"
        summary_file = output_dir / "SQL_Authorisation_Exceptions_Summary_By_Environment.csv"
        detailed_all.to_csv(detailed_file, index=False)
        summary_by_env.to_csv(summary_file, index=False)

        # Prepare data for results page
        summary_data = summary_by_env.to_dict('records')
        unique_envs = sorted(set(environments))

        return render_template(
            'results.html',
            session_id=session_id,
            env_label=", ".join(unique_envs),
            summary_data=summary_data,
            total_records=total_records,
            total_rows=total_rows_processed,
            apply_axale2_filter=apply_axale2_filter,
            environments=unique_envs
        )
        
    except Exception as e:
        # Attempt to clean any staged uploads for this session
        try:
            for p in Path(app.config['UPLOAD_FOLDER']).glob(f"{session_id}_*"):
                p.unlink(missing_ok=True)
        except Exception:
            pass
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/download/<session_id>/<filename>')
def download_file(session_id, filename):
    """Download generated output files."""
    file_path = Path(app.config['OUTPUT_FOLDER']) / session_id / filename
    
    if not file_path.exists():
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    return send_file(
        str(file_path),
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

