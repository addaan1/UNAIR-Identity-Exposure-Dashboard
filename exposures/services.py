import csv
import hashlib
import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import (
    AuditLog,
    DomainAsset,
    IdentityProfile,
    RawExposure,
    RemediationAction,
    RiskScore,
)


ROLE_NAMES = ("admin", "analyst", "reviewer")

DEFAULT_DOMAIN_ASSETS = [
    {
        "domain": "unair.ac.id",
        "display_name": "UNAIR Main Website",
        "category": DomainAsset.Category.PUBLIC,
        "unit_name": "University wide",
        "criticality": 3,
        "is_priority": True,
    },
    {
        "domain": "login.unair.ac.id",
        "display_name": "Central SSO",
        "category": DomainAsset.Category.SSO,
        "unit_name": "Directorate of Information Systems",
        "criticality": 5,
        "is_priority": True,
    },
    {
        "domain": "email.unair.ac.id",
        "display_name": "Institutional Email",
        "category": DomainAsset.Category.EMAIL,
        "unit_name": "Directorate of Information Systems",
        "criticality": 4,
        "is_priority": True,
    },
    {
        "domain": "cybercampus.unair.ac.id",
        "display_name": "Cyber Campus",
        "category": DomainAsset.Category.ACADEMIC,
        "unit_name": "Academic Administration",
        "criticality": 5,
        "is_priority": True,
    },
    {
        "domain": "e-learning.unair.ac.id",
        "display_name": "E-Learning",
        "category": DomainAsset.Category.LMS,
        "unit_name": "Learning Innovation",
        "criticality": 4,
        "is_priority": True,
    },
    {
        "domain": "fkg.unair.ac.id",
        "display_name": "Faculty of Dental Medicine",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Dental Medicine",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fst.unair.ac.id",
        "display_name": "Faculty of Science and Technology",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Science and Technology",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fib.unair.ac.id",
        "display_name": "Faculty of Humanities",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Humanities",
        "criticality": 3,
        "is_priority": False,
    },
]

DEFAULT_DUMMY_ROWS = [
    {
        "source_id": "DUMMY-001",
        "observed_at": "2026-07-01T08:45:00+07:00",
        "url": "https://login.unair.ac.id/sso/login",
        "username": "sahrul.ae",
        "email": "sahrul.ae@student.unair.ac.id",
        "exposure_types": "password,sso",
        "password_present": "true",
        "cookie_present": "false",
        "token_present": "false",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Student Affairs",
    },
    {
        "source_id": "DUMMY-002",
        "observed_at": "2026-07-02T10:20:00+07:00",
        "url": "https://cybercampus.unair.ac.id/student",
        "username": "reihan.ma",
        "email": "reihan.ma@student.unair.ac.id",
        "exposure_types": "password,academic",
        "password_present": "true",
        "cookie_present": "true",
        "token_present": "false",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Academic Administration",
    },
    {
        "source_id": "DUMMY-003",
        "observed_at": "2026-07-03T15:15:00+07:00",
        "url": "https://email.unair.ac.id/webmail",
        "username": "staff.ops",
        "email": "staff.ops@unair.ac.id",
        "exposure_types": "email,password,token",
        "password_present": "true",
        "cookie_present": "false",
        "token_present": "true",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Directorate of Information Systems",
    },
    {
        "source_id": "DUMMY-004",
        "observed_at": "2026-06-24T12:10:00+07:00",
        "url": "https://e-learning.unair.ac.id/course/view.php",
        "username": "dosen.fst",
        "email": "dosen.fst@fst.unair.ac.id",
        "exposure_types": "lms,cookie",
        "password_present": "false",
        "cookie_present": "true",
        "token_present": "false",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Faculty of Science and Technology",
    },
    {
        "source_id": "DUMMY-005",
        "observed_at": "2026-05-30T09:30:00+07:00",
        "url": "https://fkg.unair.ac.id/login",
        "username": "clinic.admin",
        "email": "clinic.admin@fkg.unair.ac.id",
        "exposure_types": "admin,password",
        "password_present": "true",
        "cookie_present": "false",
        "token_present": "false",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Faculty of Dental Medicine",
    },
    {
        "source_id": "DUMMY-006",
        "observed_at": "2026-07-04T17:45:00+07:00",
        "url": "https://fib.unair.ac.id/portal",
        "username": "portal.user",
        "email": "",
        "exposure_types": "username-only",
        "password_present": "false",
        "cookie_present": "false",
        "token_present": "false",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Faculty of Humanities",
    },
    {
        "source_id": "DUMMY-007",
        "observed_at": "2026-07-05T20:10:00+07:00",
        "url": "https://login.unair.ac.id/oauth/authorize",
        "username": "staff.ops",
        "email": "staff.ops@unair.ac.id",
        "exposure_types": "sso,cookie,token",
        "password_present": "false",
        "cookie_present": "true",
        "token_present": "true",
        "source_label": "synthetic-stealer-sample",
        "unit_hint": "Directorate of Information Systems",
    },
]


@dataclass
class ImportStats:
    imported: int = 0
    skipped_non_unair: int = 0
    duplicates: int = 0
    errors: int = 0


def normalize_domain(url):
    candidate = (url or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    domain = (parsed.netloc or parsed.path.split("/")[0]).lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_unair_domain(domain):
    domain = (domain or "").lower()
    return domain == "unair.ac.id" or domain.endswith(".unair.ac.id")


def parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def split_exposure_types(value):
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").replace("|", ",").split(",")
    return sorted({item.strip().lower() for item in items if item.strip()})


def parse_observed_at(value):
    if not value:
        return timezone.now()
    parsed = parse_datetime(str(value))
    if parsed is None:
        return timezone.now()
    if timezone.is_naive(parsed):
        return timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def stable_hash(value):
    salt = settings.SECRET_KEY.encode("utf-8")
    payload = str(value or "").strip().lower().encode("utf-8")
    return hashlib.sha256(salt + b":" + payload).hexdigest()


def mask_email(email):
    email = (email or "").strip().lower()
    if "@" not in email:
        return ""
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = f"{local[:1]}***"
    else:
        masked_local = f"{local[:2]}***{local[-1:]}"
    return f"{masked_local}@{domain}"


def mask_username(username):
    username = (username or "").strip()
    if not username:
        return ""
    if len(username) <= 3:
        return f"{username[:1]}***"
    return f"{username[:2]}***{username[-1:]}"


def build_identity_basis(row, domain):
    email = str(row.get("email") or "").strip().lower()
    username = str(row.get("username") or "").strip().lower()
    if email:
        return email
    if username:
        return f"{username}@{domain}"
    return f"unknown@{domain}"


def build_fingerprint(row, domain, exposure_types):
    parts = [
        row.get("source_id") or "",
        row.get("observed_at") or "",
        row.get("url") or "",
        row.get("username") or "",
        row.get("email") or "",
        domain,
        ",".join(exposure_types),
    ]
    return stable_hash("|".join(str(part).strip().lower() for part in parts))


def classify_account_type(email, username):
    email = (email or "").lower()
    username = (username or "").lower()
    if "@student.unair.ac.id" in email or "student" in email:
        return IdentityProfile.AccountType.STUDENT, 0.86
    if any(marker in email for marker in ("@fst.", "@fkg.", "@fib.")) or "dosen" in username:
        return IdentityProfile.AccountType.LECTURER, 0.72
    if email.endswith("@unair.ac.id") or "staff" in username or "admin" in username:
        return IdentityProfile.AccountType.STAFF, 0.78
    return IdentityProfile.AccountType.UNKNOWN, 0.45


def seed_domain_assets():
    for item in DEFAULT_DOMAIN_ASSETS:
        DomainAsset.objects.update_or_create(
            domain=item["domain"],
            defaults={
                "display_name": item["display_name"],
                "category": item["category"],
                "unit_name": item["unit_name"],
                "criticality": item["criticality"],
                "is_priority": item["is_priority"],
            },
        )


def resolve_domain_asset(domain, unit_hint=""):
    asset = DomainAsset.objects.filter(domain=domain).first()
    if asset:
        return asset
    parent_domain = ".".join(domain.split(".")[-3:]) if domain.endswith(".unair.ac.id") else ""
    parent = DomainAsset.objects.filter(domain=parent_domain).first()
    return DomainAsset.objects.create(
        domain=domain,
        display_name=domain,
        category=DomainAsset.Category.UNKNOWN,
        unit_name=unit_hint or (parent.unit_name if parent else "unknown"),
        criticality=max(2, (parent.criticality - 1) if parent else 2),
        is_priority=False,
    )


def masked_evidence_for(row, exposure_types):
    indicators = []
    if parse_bool(row.get("password_present")):
        indicators.append("password indicator")
    if parse_bool(row.get("cookie_present")):
        indicators.append("cookie indicator")
    if parse_bool(row.get("token_present")):
        indicators.append("token indicator")
    if not indicators and exposure_types:
        indicators.append(", ".join(exposure_types))
    return "Sanitized evidence: " + (", ".join(indicators) if indicators else "no secret indicator")


def calculate_risk_score(exposure):
    score = 10
    factors = ["Relevant UNAIR domain"]

    if exposure.password_present:
        score += 30
        factors.append("Password indicator present")
    if exposure.token_present:
        score += 25
        factors.append("Token indicator present")
    if exposure.cookie_present:
        score += 15
        factors.append("Cookie indicator present")

    criticality = exposure.domain_asset.criticality if exposure.domain_asset else 2
    score += criticality * 5
    factors.append(f"Domain criticality {criticality}/5")

    exposure_types = set(exposure.exposure_types or [])
    if exposure_types.intersection({"sso", "admin", "academic"}):
        score += 12
        factors.append("Sensitive system context")
    if exposure.identity_profile and exposure.identity_profile.account_type in {
        IdentityProfile.AccountType.STAFF,
        IdentityProfile.AccountType.LECTURER,
    }:
        score += 8
        factors.append("Staff or lecturer account pattern")
    if exposure.identity_profile and exposure.identity_profile.record_count > 1:
        score += min(10, exposure.identity_profile.record_count * 2)
        factors.append("Repeated identity exposure")

    age = timezone.now() - exposure.observed_at
    if age <= timedelta(days=30):
        score += 10
        factors.append("Recent observation")
    elif age <= timedelta(days=90):
        score += 5
        factors.append("Observation within 90 days")

    score = max(0, min(100, score))
    if score >= 85:
        level = RiskScore.Level.CRITICAL
    elif score >= 70:
        level = RiskScore.Level.HIGH
    elif score >= 40:
        level = RiskScore.Level.MEDIUM
    else:
        level = RiskScore.Level.LOW
    return score, level, factors


@transaction.atomic
def ingest_row(row, source_label="uploaded"):
    domain = normalize_domain(row.get("url"))
    if not is_unair_domain(domain):
        return "skipped"

    seed_domain_assets()
    exposure_types = split_exposure_types(row.get("exposure_types"))
    fingerprint = build_fingerprint(row, domain, exposure_types)
    if RawExposure.objects.filter(source_fingerprint=fingerprint).exists():
        return "duplicate"

    unit_hint = str(row.get("unit_hint") or "").strip()
    domain_asset = resolve_domain_asset(domain, unit_hint)
    identity_basis = build_identity_basis(row, domain)
    identity_hash = stable_hash(identity_basis)
    email = str(row.get("email") or "").strip().lower()
    username = str(row.get("username") or "").strip()
    account_type, confidence = classify_account_type(email, username)

    profile, _ = IdentityProfile.objects.get_or_create(
        identity_hash=identity_hash,
        defaults={
            "masked_email": mask_email(email),
            "masked_username": mask_username(username),
            "account_type": account_type,
            "unit_name": unit_hint or domain_asset.unit_name or "unknown",
            "confidence_score": confidence,
            "validation_status": IdentityProfile.ValidationStatus.NEEDS_VALIDATION,
        },
    )

    observed_at = parse_observed_at(row.get("observed_at"))
    profile.record_count = profile.record_count + 1
    profile.last_seen = max(profile.last_seen or observed_at, observed_at)
    if not profile.masked_email and email:
        profile.masked_email = mask_email(email)
    if not profile.masked_username and username:
        profile.masked_username = mask_username(username)
    if profile.unit_name == "unknown" and (unit_hint or domain_asset.unit_name):
        profile.unit_name = unit_hint or domain_asset.unit_name
    profile.save()

    source_id = str(row.get("source_id") or fingerprint[:12])
    exposure = RawExposure.objects.create(
        source_id=source_id,
        source_label=str(row.get("source_label") or source_label),
        observed_at=observed_at,
        url=str(row.get("url") or ""),
        normalized_domain=domain,
        domain_asset=domain_asset,
        identity_profile=profile,
        username_masked=mask_username(username),
        email_masked=mask_email(email),
        identity_key_hash=identity_hash,
        source_fingerprint=fingerprint,
        exposure_types=exposure_types,
        password_present=parse_bool(row.get("password_present")),
        cookie_present=parse_bool(row.get("cookie_present")),
        token_present=parse_bool(row.get("token_present")),
        unit_hint=unit_hint,
        masked_evidence=masked_evidence_for(row, exposure_types),
        metadata={
            "import_source": source_label,
            "raw_secret_storage": "not stored",
        },
    )
    score, level, factors = calculate_risk_score(exposure)
    RiskScore.objects.create(exposure=exposure, score=score, level=level, factors=factors)
    RemediationAction.objects.create(exposure=exposure)
    return "imported"


def import_rows(rows, source_label="uploaded"):
    stats = ImportStats()
    for row in rows:
        try:
            result = ingest_row(row, source_label=source_label)
        except Exception:
            stats.errors += 1
            continue
        if result == "imported":
            stats.imported += 1
        elif result == "duplicate":
            stats.duplicates += 1
        elif result == "skipped":
            stats.skipped_non_unair += 1
    return stats


def import_csv(path, source_label="uploaded"):
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    return import_rows(rows, source_label=source_label)


def reset_exposure_data():
    AuditLog.objects.all().delete()
    RemediationAction.objects.all().delete()
    RiskScore.objects.all().delete()
    RawExposure.objects.all().delete()
    IdentityProfile.objects.all().delete()


def ensure_roles_and_demo_users(create_demo_users=False):
    for role in ROLE_NAMES:
        Group.objects.get_or_create(name=role)
    if not create_demo_users:
        return

    User = get_user_model()
    password = os.getenv("DEMO_PASSWORD", "ChangeMe123!")
    users = [
        ("admin_demo", "admin"),
        ("analyst_demo", "analyst"),
        ("reviewer_demo", "reviewer"),
    ]
    for username, group_name in users:
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": f"{username}@unair.ac.id"},
        )
        if created:
            user.set_password(password)
            user.save()
        group = Group.objects.get(name=group_name)
        user.groups.add(group)
        if group_name == "admin" and not user.is_staff:
            user.is_staff = True
            user.save(update_fields=["is_staff"])
