"""WSGI config for it_audit_tools project."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'it_audit_tools.settings')

application = get_wsgi_application()
