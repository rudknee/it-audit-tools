from django.urls import path
from django.views.generic import RedirectView

from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.landing, name='landing'),
    path('review-log/', views.review_log, name='review_log'),
    path('sql-audit/', views.sql_audit, name='sql_audit'),
    path('oracle-audit/', views.oracle_audit, name='oracle_audit'),
    path(
        'oracle-audit/process/',
        views.oracle_audit_process,
        name='oracle_audit_process',
    ),
    path(
        'linux-audit/',
        RedirectView.as_view(pattern_name='audit:oracle_audit', permanent=False),
    ),
    path('linux-audit/process/', views.oracle_audit_process),
    path('upload/', views.upload_file, name='upload'),
    path(
        'download/<uuid:session_id>/<str:filename>/',
        views.download_file,
        name='download',
    ),
]
