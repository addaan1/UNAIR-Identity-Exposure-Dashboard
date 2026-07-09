from django.conf import settings
from django.db import models
from django.utils import timezone


class DomainAsset(models.Model):
    class Category(models.TextChoices):
        SSO = "sso", "SSO"
        EMAIL = "email", "Email"
        LMS = "lms", "LMS"
        ACADEMIC = "academic", "Academic"
        ADMINISTRATION = "administration", "Administration"
        FACULTY = "faculty", "Faculty"
        PUBLIC = "public", "Public"
        UNKNOWN = "unknown", "Unknown"

    domain = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    category = models.CharField(
        max_length=32, choices=Category.choices, default=Category.UNKNOWN
    )
    unit_name = models.CharField(max_length=255, default="unknown")
    criticality = models.PositiveSmallIntegerField(default=2)
    is_priority = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["domain"]

    def __str__(self):
        return self.domain


class IdentityProfile(models.Model):
    class AccountType(models.TextChoices):
        STUDENT = "student", "Student"
        STAFF = "staff", "Staff"
        LECTURER = "lecturer", "Lecturer"
        ALUMNI = "alumni", "Alumni"
        VENDOR = "vendor", "Vendor"
        UNKNOWN = "unknown", "Unknown"

    class ValidationStatus(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        NEEDS_VALIDATION = "needs_validation", "Needs validation"
        VALIDATED = "validated", "Validated"
        FALSE_POSITIVE = "false_positive", "False positive"

    identity_hash = models.CharField(max_length=64, unique=True)
    masked_email = models.CharField(max_length=255, blank=True)
    masked_username = models.CharField(max_length=255, blank=True)
    full_name = models.CharField(max_length=255, default="-")
    nim_nip = models.CharField(max_length=100, default="-")
    account_type = models.CharField(
        max_length=32, choices=AccountType.choices, default=AccountType.UNKNOWN
    )
    unit_name = models.CharField(max_length=255, default="unknown")
    confidence_score = models.DecimalField(max_digits=4, decimal_places=2, default=0)
    validation_status = models.CharField(
        max_length=32,
        choices=ValidationStatus.choices,
        default=ValidationStatus.NEEDS_VALIDATION,
    )
    record_count = models.PositiveIntegerField(default=0)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-record_count", "masked_email", "masked_username"]

    def __str__(self):
        return self.masked_email or self.masked_username or self.identity_hash[:12]


class RawExposure(models.Model):
    source_id = models.CharField(max_length=255)
    source_label = models.CharField(max_length=255, default="dummy")
    observed_at = models.DateTimeField(default=timezone.now)
    url = models.URLField(max_length=1000)
    normalized_domain = models.CharField(max_length=255, db_index=True)
    domain_asset = models.ForeignKey(
        DomainAsset,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="raw_exposures",
    )
    identity_profile = models.ForeignKey(
        IdentityProfile,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="raw_exposures",
    )
    username_masked = models.CharField(max_length=255, blank=True)
    email_masked = models.CharField(max_length=255, blank=True)
    identity_key_hash = models.CharField(max_length=64, db_index=True)
    source_fingerprint = models.CharField(max_length=64, unique=True)
    exposure_types = models.JSONField(default=list, blank=True)
    password_present = models.BooleanField(default=False)
    cookie_present = models.BooleanField(default=False)
    token_present = models.BooleanField(default=False)
    unit_hint = models.CharField(max_length=255, blank=True)
    masked_evidence = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    is_relevant = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-observed_at", "-created_at"]
        indexes = [
            models.Index(
                fields=["normalized_domain", "observed_at"],
                name="rawexp_domain_seen_idx",
            ),
            models.Index(fields=["source_label", "source_id"], name="rawexp_source_idx"),
        ]

    def __str__(self):
        return f"{self.normalized_domain} - {self.source_id}"


class RiskScore(models.Model):
    class Level(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    exposure = models.OneToOneField(
        RawExposure, on_delete=models.CASCADE, related_name="risk_score"
    )
    score = models.PositiveSmallIntegerField(default=0)
    level = models.CharField(max_length=16, choices=Level.choices, default=Level.LOW)
    factors = models.JSONField(default=list, blank=True)
    computed_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-score", "-computed_at"]

    def __str__(self):
        return f"{self.score} {self.level}"


class RemediationAction(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        REVIEW = "review", "Review"
        NOTIFIED = "notified", "Notified"
        MITIGATED = "mitigated", "Mitigated"
        RESOLVED = "resolved", "Resolved"
        FALSE_POSITIVE = "false_positive", "False positive"

    exposure = models.OneToOneField(
        RawExposure, on_delete=models.CASCADE, related_name="remediation"
    )
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.NEW)
    notes = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_remediation_actions",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="updated_remediation_actions",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["status", "-updated_at"]

    def __str__(self):
        return f"{self.exposure.source_id} - {self.status}"


class AuditLog(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="identity_dashboard_audit_logs",
    )
    event = models.CharField(max_length=100)
    object_type = models.CharField(max_length=100, blank=True)
    object_id = models.CharField(max_length=100, blank=True)
    path = models.CharField(max_length=500, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.event} by {self.actor_id or 'system'}"
