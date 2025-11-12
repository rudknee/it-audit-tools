# IT Audit Tools - Web Application

A comprehensive web application for generating exceptions registers from IT audit data, supporting both SQL Server and Linux system audits.

## Features

### SQL Server Authorisation Analysis
- **Multi-file upload**: Process multiple CAAT CSV files simultaneously
- **Environment categorization**: Organize exceptions by environment (axale, axale2, axale3, etc.)
- **8 Exception types**: Comprehensive detection of SQL Server authorization issues
- **Axale2 filter**: Optional exclusion of logins matching `^[A-Z]{2}[0-9]{4}$` pattern
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

3. Run the application:
```bash
python3 app.py
```

4. Open your browser to `http://localhost:5000`

## Usage

### SQL Server Audit

1. Navigate to `http://localhost:5000`
2. Click "Add File" to upload one or more CAAT CSV files
3. Enter environment labels for each file
4. Configure options:
   - Date format (DMY/MDY/YMD)
   - Axale2 filter (optional)
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

1. Navigate to `http://localhost:5000/linux-audit`
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
├── app.py                          # Flask application
├── sql_auth_exceptions.py          # SQL audit logic
├── templates/
│   ├── index.html                  # SQL audit upload page
│   ├── results.html                # SQL audit results page
│   └── linux_audit.html            # Linux audit (client-side)
├── static/                         # Static assets
├── uploads/                        # Temporary upload storage
├── outputs/                        # Generated output files
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Configuration

### Environment Variables

- `SECRET_KEY`: Flask secret key (default: dev key)
- `MAX_CONTENT_LENGTH`: Max upload size (default: 50MB)

Example:
```bash
export SECRET_KEY="your-production-secret-key"
python3 app.py
```

## Development

### Running in Debug Mode

The application runs in debug mode by default:
```bash
python3 app.py
```

### Production Deployment

For production, use a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Or with systemd service:

```ini
[Unit]
Description=IT Audit Tools Web Application
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/it-audit-tools
Environment="SECRET_KEY=your-secret-key"
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app

[Install]
WantedBy=multi-user.target
```

## Security Notes

- Change `SECRET_KEY` in production
- Uploaded files are automatically cleaned after processing
- Output files are stored with unique session IDs
- Linux audit tool runs entirely client-side (no data sent to server)
- Consider adding authentication for production deployments

## Dependencies

- **Flask** (≥2.0.0): Web framework
- **Werkzeug** (≥2.0.0): WSGI utilities
- **pandas** (≥1.3.0): Data processing
- **JSZip** (CDN): Client-side ZIP handling (Linux audit)

## CLI Tool

The SQL audit module can also be run from command line:

```bash
python3 sql_auth_exceptions.py \
  --input /path/to/caat.csv \
  --output-dir ./output \
  --env-label axale \
  --apply-axale2-filter true \
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

