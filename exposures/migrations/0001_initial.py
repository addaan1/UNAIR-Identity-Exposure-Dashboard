from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DomainAsset",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("domain", models.CharField(max_length=255, unique=True)),
                ("display_name", models.CharField(max_length=255)),
                ("category", models.CharField(choices=[("sso", "SSO"), ("email", "Email"), ("lms", "LMS"), ("academic", "Academic"), ("administration", "Administration"), ("faculty", "Faculty"), ("public", "Public"), ("unknown", "Unknown")], default="unknown", max_length=32)),
                ("unit_name", models.CharField(default="unknown", max_length=255)),
                ("criticality", models.PositiveSmallIntegerField(default=2)),
                ("is_priority", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["domain"]},
        ),
        migrations.CreateModel(
            name="IdentityProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("identity_hash", models.CharField(max_length=64, unique=True)),
                ("masked_email", models.CharField(blank=True, max_length=255)),
                ("masked_username", models.CharField(blank=True, max_length=255)),
                ("account_type", models.CharField(choices=[("student", "Student"), ("staff", "Staff"), ("lecturer", "Lecturer"), ("alumni", "Alumni"), ("vendor", "Vendor"), ("unknown", "Unknown")], default="unknown", max_length=32)),
                ("unit_name", models.CharField(default="unknown", max_length=255)),
                ("confidence_score", models.DecimalField(decimal_places=2, default=0, max_digits=4)),
                ("validation_status", models.CharField(choices=[("unknown", "Unknown"), ("needs_validation", "Needs validation"), ("validated", "Validated"), ("false_positive", "False positive")], default="needs_validation", max_length=32)),
                ("record_count", models.PositiveIntegerField(default=0)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-record_count", "masked_email", "masked_username"]},
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event", models.CharField(max_length=100)),
                ("object_type", models.CharField(blank=True, max_length=100)),
                ("object_id", models.CharField(blank=True, max_length=100)),
                ("path", models.CharField(blank=True, max_length=500)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="identity_dashboard_audit_logs", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="RawExposure",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_id", models.CharField(max_length=255)),
                ("source_label", models.CharField(default="dummy", max_length=255)),
                ("observed_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("url", models.URLField(max_length=1000)),
                ("normalized_domain", models.CharField(db_index=True, max_length=255)),
                ("username_masked", models.CharField(blank=True, max_length=255)),
                ("email_masked", models.CharField(blank=True, max_length=255)),
                ("identity_key_hash", models.CharField(db_index=True, max_length=64)),
                ("source_fingerprint", models.CharField(max_length=64, unique=True)),
                ("exposure_types", models.JSONField(blank=True, default=list)),
                ("password_present", models.BooleanField(default=False)),
                ("cookie_present", models.BooleanField(default=False)),
                ("token_present", models.BooleanField(default=False)),
                ("unit_hint", models.CharField(blank=True, max_length=255)),
                ("masked_evidence", models.TextField(blank=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("is_relevant", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("domain_asset", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="raw_exposures", to="exposures.domainasset")),
                ("identity_profile", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="raw_exposures", to="exposures.identityprofile")),
            ],
            options={
                "ordering": ["-observed_at", "-created_at"],
                "indexes": [
                    models.Index(fields=["normalized_domain", "observed_at"], name="rawexp_domain_seen_idx"),
                    models.Index(fields=["source_label", "source_id"], name="rawexp_source_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="RemediationAction",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("new", "New"), ("review", "Review"), ("notified", "Notified"), ("mitigated", "Mitigated"), ("resolved", "Resolved"), ("false_positive", "False positive")], default="new", max_length=32)),
                ("notes", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("exposure", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="remediation", to="exposures.rawexposure")),
                ("owner", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="owned_remediation_actions", to=settings.AUTH_USER_MODEL)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="updated_remediation_actions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["status", "-updated_at"]},
        ),
        migrations.CreateModel(
            name="RiskScore",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("score", models.PositiveSmallIntegerField(default=0)),
                ("level", models.CharField(choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")], default="low", max_length=16)),
                ("factors", models.JSONField(blank=True, default=list)),
                ("computed_at", models.DateTimeField(auto_now=True)),
                ("exposure", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="risk_score", to="exposures.rawexposure")),
            ],
            options={"ordering": ["-score", "-computed_at"]},
        ),
    ]
