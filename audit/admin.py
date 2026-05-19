from django.contrib import admin

from audit.models import ReviewRunLog


@admin.register(ReviewRunLog)
class ReviewRunLogAdmin(admin.ModelAdmin):
    list_display = (
        'started_at',
        'review_type',
        'status',
        'systems',
        'file_count',
        'exception_records',
        'findings_count',
        'duration_ms',
        'session_id',
    )
    list_filter = ('review_type', 'status', 'iapply_filter_applied', 'started_at')
    search_fields = (
        'session_id',
        'systems',
        'source_filenames',
        'error_message',
        'client_ip',
    )
    readonly_fields = (
        'id',
        'review_type',
        'status',
        'session_id',
        'started_at',
        'completed_at',
        'duration_ms',
        'systems',
        'source_filenames',
        'file_count',
        'input_rows',
        'exception_records',
        'findings_count',
        'exceptions_register_count',
        'iapply_filter_applied',
        'date_format',
        'error_message',
        'client_ip',
        'user_agent',
    )
    ordering = ('-started_at',)
    date_hierarchy = 'started_at'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
