"""ASGI config for it_audit_tools project."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'it_audit_tools.settings')

application = get_asgi_application()
