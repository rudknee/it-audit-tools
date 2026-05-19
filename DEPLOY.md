# GitHub Deployment Guide

## Quick Start

The repository is ready to push to GitHub. Follow these steps:

### 1. Create a GitHub Repository

1. Go to https://github.com/new
2. Create a new repository (e.g., `it-audit-tools`)
3. **Do NOT** initialize with README, .gitignore, or license (we already have these)
4. Copy the repository URL

### 2. Push to GitHub

Replace `yourusername` and `your-repo-name` with your actual values:

```bash
cd /Users/ghostnode/Documents/DevOps/DBs

# Add remote repository
git remote add origin https://github.com/yourusername/your-repo-name.git

# Push to GitHub
git push -u origin main
```

If you're using SSH:
```bash
git remote add origin git@github.com:yourusername/your-repo-name.git
git push -u origin main
```

### 3. Verify Deployment

Visit your repository on GitHub:
```
https://github.com/yourusername/your-repo-name
```

## What's Included

The following files have been committed:

✅ **Core Application**
- `manage.py` - Django CLI
- `it_audit_tools/` - Django project (settings, WSGI)
- `audit/` - Main app (views, URLs)
- `sql_auth_exceptions.py` - SQL audit logic
- `requirements.txt` - Python dependencies

✅ **Templates**
- `templates/index.html` - SQL audit upload page
- `templates/results.html` - SQL audit results page
- `templates/linux_audit.html` - Linux audit tool

✅ **Documentation**
- `README.md` - Comprehensive project documentation
- `.gitignore` - Git ignore rules

## What's Excluded

The following are automatically ignored (see `.gitignore`):

❌ CSV test files (`*.csv`)
❌ Upload directories (`uploads/`, `outputs/`, `out/`)
❌ Python cache (`__pycache__/`, `*.pyc`)
❌ IDE files (`.vscode/`, `.idea/`)
❌ OS files (`.DS_Store`)

## Repository Settings (Optional)

### Add Topics/Tags
Consider adding these topics to your GitHub repository:
- `audit-tools`
- `security-audit`
- `sql-server`
- `linux-security`
- `django`
- `python`
- `compliance`
- `it-audit`

### Branch Protection
For production repositories, consider:
1. Go to Settings → Branches
2. Add rule for `main` branch
3. Enable "Require pull request reviews"
4. Enable "Require status checks"

### GitHub Pages (Optional)
You can host documentation on GitHub Pages:
1. Go to Settings → Pages
2. Source: Deploy from branch `main`
3. Folder: `/docs` (if you create one)

## Collaborator Setup

If adding collaborators:

1. Go to Settings → Collaborators
2. Add team members
3. Set appropriate permissions (Read/Write/Admin)

## Continuous Integration (Optional)

Create `.github/workflows/python-app.yml` for CI:

```yaml
name: Python Application

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    - name: Lint with flake8
      run: |
        pip install flake8
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
    - name: Run tests
      run: |
        python3 sql_auth_exceptions.py --self-test
```

## Updating Repository

After making changes:

```bash
# Check status
git status

# Stage changes
git add .

# Commit changes
git commit -m "Description of changes"

# Push to GitHub
git push origin main
```

## Cloning on Another Machine

Others can clone your repository:

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
pip install -r requirements.txt
python3 manage.py runserver 0.0.0.0:8000
```

## Troubleshooting

### Authentication Issues

If you get authentication errors:

**Using HTTPS:**
```bash
# Use GitHub Personal Access Token
git remote set-url origin https://YOUR_TOKEN@github.com/yourusername/repo.git
```

**Using SSH:**
```bash
# Generate SSH key if needed
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub: Settings → SSH Keys → New SSH key
cat ~/.ssh/id_ed25519.pub
```

### Large Files

If you have files >50MB, consider Git LFS:
```bash
git lfs install
git lfs track "*.zip"
git add .gitattributes
```

## Production Deployment

For deploying to production servers:

### Using Heroku
```bash
# Install Heroku CLI
heroku create your-app-name
heroku config:set DJANGO_SECRET_KEY="your-secret-key"
git push heroku main
```

### Using Docker
Create `Dockerfile`:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "it_audit_tools.wsgi:application"]
```

### Using Ubuntu Server
```bash
# On server
git clone https://github.com/yourusername/repo.git
cd repo
pip3 install -r requirements.txt
pip3 install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 it_audit_tools.wsgi:application
```

## Security Checklist

Before deploying to production:

- [ ] Set `DJANGO_SECRET_KEY` (and `DJANGO_DEBUG=false`) via environment variables
- [ ] Review `.gitignore` to ensure no sensitive data is committed
- [ ] Add authentication if exposing to internet
- [ ] Configure HTTPS/SSL
- [ ] Set appropriate file upload limits
- [ ] Enable logging and monitoring
- [ ] Regular security updates for dependencies

## Support

For issues or questions:
- Check GitHub Issues
- Review documentation in README.md
- Contact repository maintainers

---

**Last Updated:** November 2025

