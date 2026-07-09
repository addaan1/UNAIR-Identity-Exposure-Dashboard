from django.contrib.auth.models import Group, User
from django.test import Client, TestCase
from django.urls import reverse

from .models import AuditLog, RawExposure, RemediationAction
from .services import (
    DEFAULT_DUMMY_ROWS,
    import_rows,
    is_unair_domain,
    mask_email,
    mask_username,
    normalize_domain,
    reset_exposure_data,
    seed_domain_assets,
)


class ServiceTests(TestCase):
    def setUp(self):
        seed_domain_assets()

    def test_domain_filtering(self):
        self.assertEqual(normalize_domain("https://login.unair.ac.id/sso"), "login.unair.ac.id")
        self.assertTrue(is_unair_domain("login.unair.ac.id"))
        self.assertFalse(is_unair_domain("example.com"))

    def test_masking(self):
        self.assertEqual(mask_email("staff.ops@unair.ac.id"), "staff.ops@unair.ac.id")
        self.assertEqual(mask_username("clinic.admin"), "clinic.admin")

    def test_import_dummy_data_and_deduplicate(self):
        stats = import_rows(DEFAULT_DUMMY_ROWS)
        self.assertEqual(stats.imported, len(DEFAULT_DUMMY_ROWS))
        second = import_rows(DEFAULT_DUMMY_ROWS)
        self.assertEqual(second.duplicates, len(DEFAULT_DUMMY_ROWS))
        self.assertEqual(RawExposure.objects.count(), len(DEFAULT_DUMMY_ROWS))
        self.assertTrue(RawExposure.objects.filter(risk_score__score__gte=70).exists())

    def test_non_unair_rows_are_skipped(self):
        stats = import_rows(
            [
                {
                    "source_id": "SKIP-001",
                    "url": "https://example.com/login",
                    "username": "external",
                    "email": "external@example.com",
                }
            ]
        )
        self.assertEqual(stats.skipped_non_unair, 1)
        self.assertEqual(RawExposure.objects.count(), 0)


class ViewTests(TestCase):
    def setUp(self):
        reset_exposure_data()
        seed_domain_assets()
        import_rows(DEFAULT_DUMMY_ROWS)
        Group.objects.create(name="analyst")
        self.user = User.objects.create_user("analyst", password="pass12345")
        self.user.groups.add(Group.objects.get(name="analyst"))
        self.client = Client()

    def test_login_required(self):
        response = self.client.get(reverse("overview"))
        self.assertEqual(response.status_code, 302)

    def test_dashboard_pages_render_without_raw_secret_text(self):
        self.client.login(username="analyst", password="pass12345")
        for name in ["overview", "domain_risk", "identity_exposure", "high_risk", "remediation"]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "raw-password")
            self.assertNotContains(response, "raw-token")

    def test_remediation_update_creates_audit_log(self):
        self.client.login(username="analyst", password="pass12345")
        action = RemediationAction.objects.first()
        response = self.client.post(
            reverse("remediation"),
            {"action_id": action.id, "status": "review", "notes": "Validated with mentor"},
        )
        self.assertEqual(response.status_code, 302)
        action.refresh_from_db()
        self.assertEqual(action.status, "review")
        self.assertTrue(AuditLog.objects.filter(event="update_remediation").exists())

    def test_sanitized_export(self):
        self.client.login(username="analyst", password="pass12345")
        response = self.client.get(reverse("export_exposures_csv"))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("masked_email", content)
        self.assertIn("staff.ops@unair.ac.id", content)
        self.assertNotIn("password123", content)
