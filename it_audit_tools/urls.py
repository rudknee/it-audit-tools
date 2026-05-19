"""URL configuration for it_audit_tools."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('audit.urls', namespace='audit')),
]
