# SQL Authorisation Exceptions Generator - Web Application

A Flask web application for generating SQL Server authorisation exceptions register from CAAT CSV output files.

## Features

- 📤 **File Upload**: Easy drag-and-drop CSV file upload
- ⚙️ **Configurable Options**: 
  - Environment label
  - Date format selection
  - Axale2 exclusion filter toggle
- 📊 **Results Display**: Beautiful summary table with statistics
- 📥 **Download Results**: Download detailed and summary CSV files

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

### Development Mode

```bash
python3 app.py
```

The application will start on `http://localhost:5000`

### Production Mode

For production, use a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Usage

1. Open your browser and navigate to `http://localhost:5000`
2. Click or drag-and-drop your CAAT CSV file
3. Enter an environment label (e.g., `axale`, `axale2`, `axale3`)
4. Select date format if needed
5. Optionally enable the axale2 exclusion filter
6. Click "Process File"
7. View results and download the generated CSV files

## File Structure

```
.
├── app.py                 # Flask application
├── sql_auth_exceptions.py # Core exception detection logic
├── templates/
│   ├── index.html        # Upload page
│   └── results.html      # Results display page
├── uploads/             # Temporary upload storage (auto-created)
└── outputs/              # Generated output files (auto-created)
```

## Configuration

You can configure the application by setting environment variables:

- `SECRET_KEY`: Flask secret key for sessions (default: development key)
- `MAX_CONTENT_LENGTH`: Maximum file upload size (default: 50MB)

Example:
```bash
export SECRET_KEY="your-secret-key-here"
python3 app.py
```

## Security Notes

- The application uses secure filename handling
- Uploaded files are automatically cleaned up after processing
- Output files are stored with unique session IDs
- For production, change the `SECRET_KEY` in `app.py` or set it as an environment variable

## API Endpoints

- `GET /` - Main upload page
- `POST /upload` - Process uploaded CSV file
- `GET /download/<session_id>/<filename>` - Download generated files

## Error Handling

The application handles:
- Missing files
- Invalid file types
- Missing required columns
- Date parsing errors
- Processing errors

All errors are displayed to the user with helpful messages.

