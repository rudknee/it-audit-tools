"""Persistent log of each SQL or Oracle review run."""

import uuid

from django.db import models
from django.utils import timezone


class ReviewRunLog(models.Model):
    REVIEW_SQL = 'sql'
    REVIEW_ORACLE = 'oracle'
    REVIEW_TYPE_CHOICES = [
        (REVIEW_SQL, 'SQL Server'),
        (REVIEW_ORACLE, 'Oracle'),
    ]

    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED, 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    review_type = models.CharField(max_length=16, choices=REVIEW_TYPE_CHOICES, db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, db_index=True)
    session_id = models.UUIDField(null=True, blank=True, db_index=True)

    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(default=timezone.now)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)

    systems = models.CharField(
        max_length=512,
        blank=True,
        help_text='SQL system labels or Oracle hostname',
    )
    source_filenames = models.TextField(
        blank=True,
        help_text='Comma-separated uploaded file names',
    )
    file_count = models.PositiveSmallIntegerField(default=0)

    input_rows = models.PositiveIntegerField(null=True, blank=True)
    exception_records = models.PositiveIntegerField(null=True, blank=True)
    findings_count = models.PositiveIntegerField(null=True, blank=True)
    exceptions_register_count = models.PositiveIntegerField(null=True, blank=True)

    iapply_filter_applied = models.BooleanField(default=False)
    date_format = models.CharField(max_length=8, blank=True)

    error_message = models.TextField(blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    class Meta:
        ordering = ['-started_at']
        verbose_name = 'Review run'
        verbose_name_plural = 'Review runs'
        indexes = [
            models.Index(fields=['-started_at', 'review_type']),
        ]

    def __str__(self) -> str:
        return (
            f'{self.get_review_type_display()} review '
            f'({self.get_status_display()}) at {self.started_at:%Y-%m-%d %H:%M:%S}'
        )

    @property
    def duration_display(self) -> str:
        if self.duration_ms is None:
            return '—'
        if self.duration_ms < 1000:
            return f'{self.duration_ms} ms'
        return f'{self.duration_ms / 1000:.1f} s'

    @property
    def metrics_display(self) -> str:
        if self.review_type == self.REVIEW_SQL:
            parts = []
            if self.input_rows is not None:
                parts.append(f'{self.input_rows:,} rows')
            if self.exception_records is not None:
                parts.append(f'{self.exception_records:,} exceptions')
            return ', '.join(parts) if parts else '—'
        parts = []
        if self.findings_count is not None:
            parts.append(f'{self.findings_count:,} findings')
        if self.exceptions_register_count is not None:
            parts.append(f'{self.exceptions_register_count:,} exceptions')
        return ', '.join(parts) if parts else '—'
