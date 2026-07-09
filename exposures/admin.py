from django.contrib import admin

from .models import (
    AuditLog,
    DomainAsset,
    IdentityProfile,
    RawExposure,
    RemediationAction,
    RiskScore,
)


@admin.register(DomainAsset)
class DomainAssetAdmin(admin.ModelAdmin):
    list_display = ("domain", "category", "unit_name", "criticality", "is_priority")
    list_filter = ("category", "is_priority", "criticality")
    search_fields = ("domain", "display_name", "unit_name")


@admin.register(IdentityProfile)
class IdentityProfileAdmin(admin.ModelAdmin):
    list_display = (
        "masked_email",
        "masked_username",
        "account_type",
        "unit_name",
        "confidence_score",
        "record_count",
        "validation_status",
    )
    list_filter = ("account_type", "validation_status", "unit_name")
    search_fields = ("masked_email", "masked_username", "identity_hash")
    readonly_fields = ("identity_hash", "created_at", "updated_at")


class RiskScoreInline(admin.StackedInline):
    model = RiskScore
    extra = 0
    readonly_fields = ("computed_at",)


class RemediationActionInline(admin.StackedInline):
    model = RemediationAction
    extra = 0
    readonly_fields = ("created_at", "updated_at")


@admin.register(RawExposure)
class RawExposureAdmin(admin.ModelAdmin):
    list_display = (
        "source_id",
        "normalized_domain",
        "email_masked",
        "username_masked",
        "observed_at",
        "source_label",
    )
    list_filter = (
        "source_label",
        "normalized_domain",
        "password_present",
        "cookie_present",
        "token_present",
    )
    search_fields = (
        "source_id",
        "normalized_domain",
        "email_masked",
        "username_masked",
        "masked_evidence",
    )
    readonly_fields = ("identity_key_hash", "source_fingerprint", "created_at")
    inlines = [RiskScoreInline, RemediationActionInline]


@admin.register(RiskScore)
class RiskScoreAdmin(admin.ModelAdmin):
    list_display = ("exposure", "score", "level", "computed_at")
    list_filter = ("level",)
    search_fields = ("exposure__source_id", "exposure__normalized_domain")


@admin.register(RemediationAction)
class RemediationActionAdmin(admin.ModelAdmin):
    list_display = ("exposure", "status", "owner", "updated_by", "updated_at")
    list_filter = ("status",)
    search_fields = ("exposure__source_id", "notes")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("event", "actor", "object_type", "object_id", "created_at")
    list_filter = ("event", "object_type")
    search_fields = ("event", "object_type", "object_id", "path")
    readonly_fields = ("created_at",)
