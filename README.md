# IT Audit Tools - Web Application

A comprehensive **Django** web application for generating exceptions registers from IT audit data, supporting both SQL Server and Linux system audits.

## Features

### SQL Server Authorisation Analysis
- **Multi-file upload**: Process multiple CAAT CSV files simultaneously
- **Environment categorization**: Organize exceptions by environment (e.g. axale, iApply, axale3)
- **8 Exception types**: Comprehensive detection of SQL Server authorization issues
- **iApply exclusion filter** (CLI/UI flag `apply_iapply_filter`): Optional exclusion of iApply logins matching `^[A-Z]{2}[0-9]{4}$` from E1–E3
- **Flexible date parsing**: Supports DMY, MDY, and YMD formats
- **Combined reports**: Download detailed exceptions and summary CSVs

### Linux Audit Review Tool
- **Client-side processing**: All analysis runs in the browser (no backend required)
- **ZIP file support**: Upload audit ZIP files containing system configuration
- **20+ Security controls**: Comprehensive Linux security baseline checks
- **Auto-generated exceptions**: Creates exceptions register from findings
- **Filterable results**: Search and sort findings and exceptions
- **CSV exports**: Download findings and exceptions separately or combined

## Installation

### Prerequisites
- Python 3.9+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/it-audit-tools.git
cd it-audit-tools
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run database migrations (first time only):
```bash
python3 manage.py migrate
```

4. Run the development server:
```bash
python3 manage.py runserver 0.0.0.0:8000
```

5. Open your browser to `http://localhost:8000`

## Usage

### SQL Server Audit

1. Navigate to `http://localhost:8000`
2. Click "Add File" to upload one or more CAAT CSV files
3. Enter environment labels for each file
4. Configure options:
   - Date format (DMY/MDY/YMD)
   - iApply exclusion filter (optional)
5. Click "Process Files"
6. Download results:
   - Combined detailed exceptions CSV
   - Summary by environment CSV

#### Expected CSV Format
- Row 0: Metadata (ignored)
- Row 1: Column headers
- Row 2+: Data rows

#### Exception Types Detected

1. **E1**: SQL logins without password policy
2. **E2**: SQL logins without password expiration
3. **E3**: Active logins with password older than 365 days
4. **E4**: Powerful server roles/permissions
5. **E5**: db_owner role membership
6. **E6**: Direct object-level grants to users
7. **E7**: Orphaned database users (deduplicated per database)
8. **E8**: Disabled accounts with powerful access

### Linux Audit Review

1. Navigate to `http://localhost:8000/linux-audit/`
2. Upload a Linux audit ZIP file
3. View system summary and findings
4. Review auto-generated exceptions register
5. Export results:
   - Findings CSV
   - Exceptions register CSV
   - Combined ZIP

#### Supported Files in ZIP

- `SystemInformation.txt` (semicolon-separated)
- `Sshdconfig.txt`
- `passwordquality.txt`
- `faillockconfig.txt`
- `Userinformation.txt`
- `Passwordinformation.txt`
- `Lastlogininformation.txt`
- `riskyServices.txt`
- `rhosts.txt`
- `Sudoers.txt`

#### Security Controls Checked

**SSH Configuration**
- Root login permissions
- Password authentication
- Public key authentication
- Empty passwords policy
- Max authentication tries
- Session limits
- Client alive timeouts
- TCP/X11 forwarding
- Hostbased authentication

**Password & Account Management**
- Password quality (pwquality)
- Account lockout (faillock)
- Unlocked local accounts
- Dormant accounts (≥90 days)

**System Security**
- Risky legacy services
- .rhosts trust files
- Sudoers privileges
- UID 0 accounts
- Duplicate UIDs
- System accounts with shells

## Project Structure

```
.
├── manage.py                       # Django CLI
├── it_audit_tools/                 # Project settings & URLs
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── audit/                          # Main web app (views, URLs)
│   ├── views.py
│   └── urls.py
├── sql_auth_exceptions.py          # SQL audit logic
├── templates/
│   ├── landing.html
│   ├── index.html                  # SQL audit upload page
│   ├── results.html                # SQL audit results page
│   └── linux_audit.html            # Linux audit (client-side)
├── uploads/                        # Temporary upload storage
├── outputs/                        # Generated output files
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Configuration

### Environment Variables

- `DJANGO_SECRET_KEY`: Django secret key (defaults to an insecure dev key if unset)
- `DJANGO_DEBUG`: Set to `false` in production
- `DJANGO_ALLOWED_HOSTS`: Comma-separated hosts (default: `localhost,127.0.0.1`)

Example:
```bash
export DJANGO_SECRET_KEY="your-production-secret-key"
export DJANGO_DEBUG="false"
export DJANGO_ALLOWED_HOSTS="yourdomain.com,www.yourdomain.com"
python3 manage.py runserver 0.0.0.0:8000
```

## Development

### Running in Debug Mode

```bash
python3 manage.py runserver
```

### Production Deployment

Use Gunicorn with the Django WSGI application:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 it_audit_tools.wsgi:application
```

Or with systemd service:

```ini
[Unit]
Description=IT Audit Tools Web Application
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/it-audit-tools
Environment="DJANGO_SECRET_KEY=your-secret-key"
Environment="DJANGO_DEBUG=false"
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:8000 it_audit_tools.wsgi:application

[Install]
WantedBy=multi-user.target
```

## Security Notes

- Set `DJANGO_SECRET_KEY` in production
- Uploaded files are automatically cleaned after processing
- Output files are stored with unique session IDs
- Linux audit tool runs entirely client-side (no data sent to server)
- Consider adding authentication for production deployments

## Dependencies

- **Django** (4.2+): Web framework
- **pandas** (≥1.3.0): Data processing
- **JSZip** (CDN): Client-side ZIP handling (Linux audit)

## CLI Tool

The SQL audit module can also be run from command line. Use ``--apply-iapply-filter`` to apply the iApply login exclusion to E1–E3.

```bash
python3 sql_auth_exceptions.py \
  --input /path/to/caat.csv \
  --output-dir ./output \
  --env-label axale \
  --apply-iapply-filter true \
  --verbose

# Self-test
python3 sql_auth_exceptions.py --self-test
```

## Color Scheme

The application uses a professional color palette:
- Primary: `#0055c6` (blue)
- Dark: `#37373f` (charcoal)
- Gray: `#707070` (medium gray)
- Warning: `#ffe200` (yellow)
- Error: `#f0453a` (red)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is intended for internal IT audit use.

## Support

For issues or questions:
1. Check existing documentation
2. Review error logs
3. Contact the development team

## Changelog

### Version 1.1.0
- Migrated web UI from Flask to Django

### Version 1.0.0
- SQL Server authorisation analysis with multi-file support
- Linux audit review tool (client-side)
- Combined exception registers
- CSV export functionality
- Modern responsive UI

## Acknowledgments

- Based on IT-Audit-Tools CAAT scripts
- Implements security baseline checks from industry standards
- Uses JSZip for client-side file processing

