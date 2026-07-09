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
    # --- Critical infrastructure ---
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
        "display_name": "E-Learning (AULA)",
        "category": DomainAsset.Category.LMS,
        "unit_name": "Learning Innovation",
        "criticality": 4,
        "is_priority": True,
    },
    {
        "domain": "repository.unair.ac.id",
        "display_name": "Institutional Repository",
        "category": DomainAsset.Category.ACADEMIC,
        "unit_name": "Library & Knowledge Center",
        "criticality": 3,
        "is_priority": True,
    },
    {
        "domain": "siakad.unair.ac.id",
        "display_name": "Academic Information System",
        "category": DomainAsset.Category.ACADEMIC,
        "unit_name": "Academic Administration",
        "criticality": 5,
        "is_priority": True,
    },
    {
        "domain": "sinta.unair.ac.id",
        "display_name": "SINTA Research Portal",
        "category": DomainAsset.Category.ACADEMIC,
        "unit_name": "Research & Innovation",
        "criticality": 3,
        "is_priority": False,
    },
    # --- 15 Faculties ---
    {
        "domain": "fk.unair.ac.id",
        "display_name": "Faculty of Medicine",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Medicine",
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
        "domain": "fh.unair.ac.id",
        "display_name": "Faculty of Law",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Law",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "feb.unair.ac.id",
        "display_name": "Faculty of Economics and Business",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Economics and Business",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fisip.unair.ac.id",
        "display_name": "Faculty of Social and Political Sciences",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Social and Political Sciences",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fpsi.unair.ac.id",
        "display_name": "Faculty of Psychology",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Psychology",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fkp.unair.ac.id",
        "display_name": "Faculty of Nursing",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Nursing",
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
    {
        "domain": "fpk.unair.ac.id",
        "display_name": "Faculty of Fisheries and Marine",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Fisheries and Marine",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "ff.unair.ac.id",
        "display_name": "Faculty of Pharmacy",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Pharmacy",
        "criticality": 4,
        "is_priority": False,
    },
    {
        "domain": "fkh.unair.ac.id",
        "display_name": "Faculty of Veterinary Medicine",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Veterinary Medicine",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fkm.unair.ac.id",
        "display_name": "Faculty of Public Health",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Public Health",
        "criticality": 3,
        "is_priority": False,
    },
    {
        "domain": "fv.unair.ac.id",
        "display_name": "Faculty of Vocational Studies",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Vocational Studies",
        "criticality": 2,
        "is_priority": False,
    },
    {
        "domain": "fkdk.unair.ac.id",
        "display_name": "Faculty of Advanced Technology and Multidiscipline",
        "category": DomainAsset.Category.FACULTY,
        "unit_name": "Faculty of Advanced Technology and Multidiscipline",
        "criticality": 3,
        "is_priority": False,
    },
]

# fmt: off
DEFAULT_DUMMY_ROWS = [
    # ──── January 2026 ────
    {"source_id": "SYNTH-001", "observed_at": "2026-01-05T09:12:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fk.2023", "email": "mhs.fk.2023@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-002", "observed_at": "2026-01-08T14:30:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.feb.2024", "email": "mhs.feb.2024@student.unair.ac.id", "exposure_types": "password,academic", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-003", "observed_at": "2026-01-12T11:05:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fh.01", "email": "dosen.fh.01@fh.unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Law"},
    {"source_id": "SYNTH-004", "observed_at": "2026-01-15T16:45:00+07:00", "url": "https://e-learning.unair.ac.id/course/view.php", "username": "mhs.fisip.2022", "email": "mhs.fisip.2022@student.unair.ac.id", "exposure_types": "lms,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Social and Political Sciences"},
    {"source_id": "SYNTH-005", "observed_at": "2026-01-19T08:20:00+07:00", "url": "https://siakad.unair.ac.id/portal", "username": "mhs.fpsi.2023", "email": "mhs.fpsi.2023@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Psychology"},
    {"source_id": "SYNTH-006", "observed_at": "2026-01-22T13:55:00+07:00", "url": "https://fk.unair.ac.id/portal/login", "username": "admin.fk", "email": "admin.fk@fk.unair.ac.id", "exposure_types": "admin,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-007", "observed_at": "2026-01-25T10:30:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.rektorat", "email": "staff.rektorat@unair.ac.id", "exposure_types": "sso,cookie,token", "password_present": "false", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Rectorate"},
    {"source_id": "SYNTH-008", "observed_at": "2026-01-28T19:15:00+07:00", "url": "https://repository.unair.ac.id/upload", "username": "mhs.fst.2024", "email": "mhs.fst.2024@student.unair.ac.id", "exposure_types": "academic,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Science and Technology"},
    # ──── February 2026 ────
    {"source_id": "SYNTH-009", "observed_at": "2026-02-02T08:45:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkp.2023", "email": "mhs.fkp.2023@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Nursing"},
    {"source_id": "SYNTH-010", "observed_at": "2026-02-05T11:30:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fkg.2024", "email": "mhs.fkg.2024@student.unair.ac.id", "exposure_types": "password,academic", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Dental Medicine"},
    {"source_id": "SYNTH-011", "observed_at": "2026-02-08T14:20:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.feb.01", "email": "dosen.feb.01@feb.unair.ac.id", "exposure_types": "email,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-012", "observed_at": "2026-02-11T09:10:00+07:00", "url": "https://e-learning.unair.ac.id/mod/assign/view.php", "username": "dosen.fib.02", "email": "dosen.fib.02@fib.unair.ac.id", "exposure_types": "lms,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Humanities"},
    {"source_id": "SYNTH-013", "observed_at": "2026-02-14T17:40:00+07:00", "url": "https://ff.unair.ac.id/admin", "username": "admin.ff", "email": "admin.ff@ff.unair.ac.id", "exposure_types": "admin,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Pharmacy"},
    {"source_id": "SYNTH-014", "observed_at": "2026-02-17T12:25:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkh.2022", "email": "mhs.fkh.2022@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Veterinary Medicine"},
    {"source_id": "SYNTH-015", "observed_at": "2026-02-20T15:50:00+07:00", "url": "https://siakad.unair.ac.id/student/grades", "username": "mhs.fkm.2023", "email": "mhs.fkm.2023@student.unair.ac.id", "exposure_types": "academic,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Public Health"},
    {"source_id": "SYNTH-016", "observed_at": "2026-02-23T10:15:00+07:00", "url": "https://cybercampus.unair.ac.id/lecturer", "username": "dosen.fpk.01", "email": "dosen.fpk.01@fpk.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Fisheries and Marine"},
    {"source_id": "SYNTH-017", "observed_at": "2026-02-26T20:05:00+07:00", "url": "https://fv.unair.ac.id/portal", "username": "mhs.fv.2024", "email": "mhs.fv.2024@student.unair.ac.id", "exposure_types": "password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Vocational Studies"},
    # ──── March 2026 ────
    {"source_id": "SYNTH-018", "observed_at": "2026-03-01T07:30:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkdk.2023", "email": "mhs.fkdk.2023@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Advanced Technology and Multidiscipline"},
    {"source_id": "SYNTH-019", "observed_at": "2026-03-04T13:45:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "staff.perpustakaan", "email": "staff.perpustakaan@unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Library & Knowledge Center"},
    {"source_id": "SYNTH-020", "observed_at": "2026-03-07T16:20:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fk.2022", "email": "mhs.fk.2022@student.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-021", "observed_at": "2026-03-10T11:10:00+07:00", "url": "https://e-learning.unair.ac.id/course/view.php", "username": "dosen.fk.03", "email": "dosen.fk.03@fk.unair.ac.id", "exposure_types": "lms,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-022", "observed_at": "2026-03-13T09:35:00+07:00", "url": "https://sinta.unair.ac.id/author/profile", "username": "dosen.fisip.02", "email": "dosen.fisip.02@fisip.unair.ac.id", "exposure_types": "academic,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Social and Political Sciences"},
    {"source_id": "SYNTH-023", "observed_at": "2026-03-16T14:50:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.kemahasiswaan", "email": "staff.kemahasiswaan@unair.ac.id", "exposure_types": "sso,token", "password_present": "false", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Student Affairs"},
    {"source_id": "SYNTH-024", "observed_at": "2026-03-19T18:25:00+07:00", "url": "https://feb.unair.ac.id/admin/dashboard", "username": "admin.feb", "email": "admin.feb@feb.unair.ac.id", "exposure_types": "admin,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-025", "observed_at": "2026-03-22T08:00:00+07:00", "url": "https://siakad.unair.ac.id/student/krs", "username": "mhs.fpsi.2024", "email": "mhs.fpsi.2024@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Psychology"},
    {"source_id": "SYNTH-026", "observed_at": "2026-03-25T21:15:00+07:00", "url": "https://fkp.unair.ac.id/portal", "username": "dosen.fkp.01", "email": "dosen.fkp.01@fkp.unair.ac.id", "exposure_types": "password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Nursing"},
    {"source_id": "SYNTH-027", "observed_at": "2026-03-28T12:40:00+07:00", "url": "https://repository.unair.ac.id/submit", "username": "mhs.fib.2023", "email": "mhs.fib.2023@student.unair.ac.id", "exposure_types": "academic", "password_present": "false", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Humanities"},
    # ──── April 2026 ────
    {"source_id": "SYNTH-028", "observed_at": "2026-04-01T09:20:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.ff.2023", "email": "mhs.ff.2023@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Pharmacy"},
    {"source_id": "SYNTH-029", "observed_at": "2026-04-03T15:10:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fh.2024", "email": "mhs.fh.2024@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Law"},
    {"source_id": "SYNTH-030", "observed_at": "2026-04-05T10:45:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fst.02", "email": "dosen.fst.02@fst.unair.ac.id", "exposure_types": "email,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Science and Technology"},
    {"source_id": "SYNTH-031", "observed_at": "2026-04-08T14:30:00+07:00", "url": "https://e-learning.unair.ac.id/mod/quiz/view.php", "username": "mhs.fkm.2024", "email": "mhs.fkm.2024@student.unair.ac.id", "exposure_types": "lms,cookie,password", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Public Health"},
    {"source_id": "SYNTH-032", "observed_at": "2026-04-11T17:55:00+07:00", "url": "https://fisip.unair.ac.id/admin", "username": "admin.fisip", "email": "admin.fisip@fisip.unair.ac.id", "exposure_types": "admin,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Social and Political Sciences"},
    {"source_id": "SYNTH-033", "observed_at": "2026-04-14T08:15:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fpk.2022", "email": "mhs.fpk.2022@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Fisheries and Marine"},
    {"source_id": "SYNTH-034", "observed_at": "2026-04-17T11:40:00+07:00", "url": "https://siakad.unair.ac.id/student/transkrip", "username": "mhs.fkg.2022", "email": "mhs.fkg.2022@student.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Dental Medicine"},
    {"source_id": "SYNTH-035", "observed_at": "2026-04-20T19:30:00+07:00", "url": "https://fkh.unair.ac.id/lab-portal", "username": "dosen.fkh.01", "email": "dosen.fkh.01@fkh.unair.ac.id", "exposure_types": "password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Veterinary Medicine"},
    {"source_id": "SYNTH-036", "observed_at": "2026-04-23T13:05:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "staff.keuangan", "email": "staff.keuangan@unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Finance Division"},
    {"source_id": "SYNTH-037", "observed_at": "2026-04-26T16:20:00+07:00", "url": "https://cybercampus.unair.ac.id/lecturer", "username": "dosen.fkdk.01", "email": "dosen.fkdk.01@fkdk.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Advanced Technology and Multidiscipline"},
    {"source_id": "SYNTH-038", "observed_at": "2026-04-29T07:45:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.it.security", "email": "staff.it.security@unair.ac.id", "exposure_types": "sso,cookie,token", "password_present": "false", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Directorate of Information Systems"},
    # ──── May 2026 ────
    {"source_id": "SYNTH-039", "observed_at": "2026-05-02T09:30:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fk.2024", "email": "mhs.fk.2024@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-040", "observed_at": "2026-05-04T12:15:00+07:00", "url": "https://e-learning.unair.ac.id/course/view.php", "username": "mhs.feb.2023", "email": "mhs.feb.2023@student.unair.ac.id", "exposure_types": "lms,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-041", "observed_at": "2026-05-07T15:50:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fpsi.01", "email": "dosen.fpsi.01@fpsi.unair.ac.id", "exposure_types": "email,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Psychology"},
    {"source_id": "SYNTH-042", "observed_at": "2026-05-10T10:05:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fh.2023", "email": "mhs.fh.2023@student.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Law"},
    {"source_id": "SYNTH-043", "observed_at": "2026-05-13T18:30:00+07:00", "url": "https://fkg.unair.ac.id/klinik/login", "username": "admin.klinik.fkg", "email": "admin.klinik.fkg@fkg.unair.ac.id", "exposure_types": "admin,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Dental Medicine"},
    {"source_id": "SYNTH-044", "observed_at": "2026-05-16T08:45:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkp.2024", "email": "mhs.fkp.2024@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Nursing"},
    {"source_id": "SYNTH-045", "observed_at": "2026-05-19T14:20:00+07:00", "url": "https://siakad.unair.ac.id/student/krs", "username": "mhs.fst.2023", "email": "mhs.fst.2023@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Science and Technology"},
    {"source_id": "SYNTH-046", "observed_at": "2026-05-22T11:35:00+07:00", "url": "https://repository.unair.ac.id/submit", "username": "dosen.fkm.01", "email": "dosen.fkm.01@fkm.unair.ac.id", "exposure_types": "academic,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Public Health"},
    {"source_id": "SYNTH-047", "observed_at": "2026-05-25T16:10:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "staff.sdm", "email": "staff.sdm@unair.ac.id", "exposure_types": "email,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Human Resources"},
    {"source_id": "SYNTH-048", "observed_at": "2026-05-28T19:45:00+07:00", "url": "https://fv.unair.ac.id/siakad", "username": "mhs.fv.2023", "email": "mhs.fv.2023@student.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Vocational Studies"},
    {"source_id": "SYNTH-049", "observed_at": "2026-05-30T09:30:00+07:00", "url": "https://fkg.unair.ac.id/login", "username": "clinic.admin", "email": "clinic.admin@fkg.unair.ac.id", "exposure_types": "admin,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Dental Medicine"},
    # ──── June 2026 ────
    {"source_id": "SYNTH-050", "observed_at": "2026-06-01T08:00:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fisip.2024", "email": "mhs.fisip.2024@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Social and Political Sciences"},
    {"source_id": "SYNTH-051", "observed_at": "2026-06-03T13:25:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.ff.2024", "email": "mhs.ff.2024@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Pharmacy"},
    {"source_id": "SYNTH-052", "observed_at": "2026-06-05T16:40:00+07:00", "url": "https://e-learning.unair.ac.id/mod/forum/view.php", "username": "dosen.ff.02", "email": "dosen.ff.02@ff.unair.ac.id", "exposure_types": "lms,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Pharmacy"},
    {"source_id": "SYNTH-053", "observed_at": "2026-06-08T10:15:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fv.01", "email": "dosen.fv.01@fv.unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Vocational Studies"},
    {"source_id": "SYNTH-054", "observed_at": "2026-06-11T14:55:00+07:00", "url": "https://siakad.unair.ac.id/lecturer", "username": "dosen.fk.04", "email": "dosen.fk.04@fk.unair.ac.id", "exposure_types": "academic,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-055", "observed_at": "2026-06-14T08:30:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkh.2024", "email": "mhs.fkh.2024@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Veterinary Medicine"},
    {"source_id": "SYNTH-056", "observed_at": "2026-06-17T11:45:00+07:00", "url": "https://fpsi.unair.ac.id/lab/portal", "username": "admin.lab.fpsi", "email": "admin.lab.fpsi@fpsi.unair.ac.id", "exposure_types": "admin,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Psychology"},
    {"source_id": "SYNTH-057", "observed_at": "2026-06-20T15:20:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fib.2024", "email": "mhs.fib.2024@student.unair.ac.id", "exposure_types": "academic,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Humanities"},
    {"source_id": "SYNTH-058", "observed_at": "2026-06-22T18:10:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.baa", "email": "staff.baa@unair.ac.id", "exposure_types": "sso,cookie,token", "password_present": "false", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Academic Administration Bureau"},
    {"source_id": "SYNTH-059", "observed_at": "2026-06-24T12:10:00+07:00", "url": "https://e-learning.unair.ac.id/course/view.php", "username": "dosen.fst.01", "email": "dosen.fst.01@fst.unair.ac.id", "exposure_types": "lms,cookie", "password_present": "false", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Science and Technology"},
    {"source_id": "SYNTH-060", "observed_at": "2026-06-26T09:50:00+07:00", "url": "https://fkdk.unair.ac.id/portal/login", "username": "mhs.fkdk.2024", "email": "mhs.fkdk.2024@student.unair.ac.id", "exposure_types": "password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Advanced Technology and Multidiscipline"},
    {"source_id": "SYNTH-061", "observed_at": "2026-06-28T20:30:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "staff.humas", "email": "staff.humas@unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Public Relations"},
    # ──── July 2026 (recent/critical) ────
    {"source_id": "SYNTH-062", "observed_at": "2026-07-01T08:45:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fk.2025", "email": "mhs.fk.2025@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-063", "observed_at": "2026-07-01T10:20:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.feb.2025", "email": "mhs.feb.2025@student.unair.ac.id", "exposure_types": "password,academic", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-064", "observed_at": "2026-07-02T15:15:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "staff.ops", "email": "staff.ops@unair.ac.id", "exposure_types": "email,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Directorate of Information Systems"},
    {"source_id": "SYNTH-065", "observed_at": "2026-07-02T17:45:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkg.2025", "email": "mhs.fkg.2025@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Dental Medicine"},
    {"source_id": "SYNTH-066", "observed_at": "2026-07-03T08:30:00+07:00", "url": "https://siakad.unair.ac.id/student/khs", "username": "mhs.fh.2025", "email": "mhs.fh.2025@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Law"},
    {"source_id": "SYNTH-067", "observed_at": "2026-07-03T13:10:00+07:00", "url": "https://e-learning.unair.ac.id/mod/assign/view.php", "username": "dosen.feb.02", "email": "dosen.feb.02@feb.unair.ac.id", "exposure_types": "lms,password,cookie,token", "password_present": "true", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-068", "observed_at": "2026-07-03T19:50:00+07:00", "url": "https://fk.unair.ac.id/research/portal", "username": "admin.riset.fk", "email": "admin.riset.fk@fk.unair.ac.id", "exposure_types": "admin,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-069", "observed_at": "2026-07-04T09:15:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fisip.2025", "email": "mhs.fisip.2025@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Social and Political Sciences"},
    {"source_id": "SYNTH-070", "observed_at": "2026-07-04T14:40:00+07:00", "url": "https://cybercampus.unair.ac.id/lecturer", "username": "dosen.fkm.02", "email": "dosen.fkm.02@fkm.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Public Health"},
    {"source_id": "SYNTH-071", "observed_at": "2026-07-04T17:45:00+07:00", "url": "https://fib.unair.ac.id/portal", "username": "portal.user.fib", "email": "", "exposure_types": "username-only", "password_present": "false", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Humanities"},
    {"source_id": "SYNTH-072", "observed_at": "2026-07-05T08:00:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fpk.02", "email": "dosen.fpk.02@fpk.unair.ac.id", "exposure_types": "email,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Fisheries and Marine"},
    {"source_id": "SYNTH-073", "observed_at": "2026-07-05T11:25:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.ops", "email": "staff.ops@unair.ac.id", "exposure_types": "sso,cookie,token", "password_present": "false", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Directorate of Information Systems"},
    {"source_id": "SYNTH-074", "observed_at": "2026-07-05T16:55:00+07:00", "url": "https://ff.unair.ac.id/research/submit", "username": "dosen.ff.03", "email": "dosen.ff.03@ff.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Pharmacy"},
    {"source_id": "SYNTH-075", "observed_at": "2026-07-06T09:30:00+07:00", "url": "https://siakad.unair.ac.id/student/krs", "username": "mhs.fkp.2025", "email": "mhs.fkp.2025@student.unair.ac.id", "exposure_types": "academic,password,cookie", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Nursing"},
    {"source_id": "SYNTH-076", "observed_at": "2026-07-06T14:10:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fst.2025", "email": "mhs.fst.2025@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Science and Technology"},
    {"source_id": "SYNTH-077", "observed_at": "2026-07-06T18:45:00+07:00", "url": "https://fkh.unair.ac.id/klinik/login", "username": "admin.klinik.fkh", "email": "admin.klinik.fkh@fkh.unair.ac.id", "exposure_types": "admin,password,cookie,token", "password_present": "true", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Veterinary Medicine"},
    {"source_id": "SYNTH-078", "observed_at": "2026-07-07T10:20:00+07:00", "url": "https://cybercampus.unair.ac.id/student", "username": "mhs.fpsi.2025", "email": "mhs.fpsi.2025@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Psychology"},
    {"source_id": "SYNTH-079", "observed_at": "2026-07-07T15:35:00+07:00", "url": "https://e-learning.unair.ac.id/mod/quiz/attempt.php", "username": "mhs.fv.2025", "email": "mhs.fv.2025@student.unair.ac.id", "exposure_types": "lms,cookie,password", "password_present": "true", "cookie_present": "true", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Vocational Studies"},
    {"source_id": "SYNTH-080", "observed_at": "2026-07-08T08:15:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fkdk.2025", "email": "mhs.fkdk.2025@student.unair.ac.id", "exposure_types": "sso,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Advanced Technology and Multidiscipline"},
    {"source_id": "SYNTH-081", "observed_at": "2026-07-08T12:50:00+07:00", "url": "https://email.unair.ac.id/webmail", "username": "dosen.fh.02", "email": "dosen.fh.02@fh.unair.ac.id", "exposure_types": "email,password,token", "password_present": "true", "cookie_present": "false", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Law"},
    {"source_id": "SYNTH-082", "observed_at": "2026-07-08T17:30:00+07:00", "url": "https://fkm.unair.ac.id/admin", "username": "admin.fkm", "email": "admin.fkm@fkm.unair.ac.id", "exposure_types": "admin,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Public Health"},
    {"source_id": "SYNTH-083", "observed_at": "2026-07-09T07:00:00+07:00", "url": "https://login.unair.ac.id/sso/login", "username": "mhs.fk.maba", "email": "mhs.fk.maba@student.unair.ac.id", "exposure_types": "password,sso", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Medicine"},
    {"source_id": "SYNTH-084", "observed_at": "2026-07-09T10:30:00+07:00", "url": "https://siakad.unair.ac.id/student/krs", "username": "mhs.feb.maba", "email": "mhs.feb.maba@student.unair.ac.id", "exposure_types": "academic,password", "password_present": "true", "cookie_present": "false", "token_present": "false", "source_label": "synthetic-stealer-log", "unit_hint": "Faculty of Economics and Business"},
    {"source_id": "SYNTH-085", "observed_at": "2026-07-09T13:15:00+07:00", "url": "https://login.unair.ac.id/oauth/authorize", "username": "staff.warek", "email": "staff.warek@unair.ac.id", "exposure_types": "sso,cookie,token,password", "password_present": "true", "cookie_present": "true", "token_present": "true", "source_label": "synthetic-stealer-log", "unit_hint": "Rectorate"},
]
# fmt: on


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
    return (email or "").strip().lower()


def mask_username(username):
    return (username or "").strip()


def generate_synthetic_identity_details(email, username, account_type):
    # Deterministic generation using email/username hash to keep it consistent
    h = hashlib.md5(str(email or username or "").encode('utf-8')).hexdigest()
    val = int(h[:6], 16)
    
    first_names = ["Ahmad", "Budi", "Chandra", "Dedi", "Eko", "Fahmi", "Gunawan", "Hendra", "Indra", "Joko", "Kurniawan", "Lukman", "Mulyadi", "Nugroho", "Oki", "Prabowo", "Rian", "Setyawan", "Taufik", "Wahyu", "Yanto", "Diar", "Aditya", "Rizal", "Arif", "Hafiz", "Bayu", "Fajar"]
    last_names = ["Saputra", "Wibowo", "Hidayat", "Santoso", "Pratama", "Kurnia", "Wijaya", "Setiawan", "Nugraha", "Raharjo", "Budiman", "Susanto", "Laksana", "Hadi", "Firmansyah", "Gunawan", "Utomo", "Kusuma", "Lutfi", "Putra", "Pradana"]
    
    first = first_names[val % len(first_names)]
    last = last_names[(val // len(first_names)) % len(last_names)]
    
    if account_type in [IdentityProfile.AccountType.LECTURER, "lecturer"]:
        titles_pre = ["Dr.", "Prof. Dr.", "Ir.", "Dr. Eng."]
        titles_post = ["M.T.", "M.Cs.", "M.Kom.", "S.T., M.T.", "S.Si., M.Si.", "S.H., M.Hum."]
        name = f"{titles_pre[val % len(titles_pre)]} {first} {last}, {titles_post[val % len(titles_post)]}"
        nip = f"19{70 + (val % 20):02d}{1 + (val % 12):02d}{1 + (val % 28):02d}{2010 + (val % 15):02d}{1 + (val % 2)}{101 + (val % 50)}"
        return name, nip
    elif account_type in [IdentityProfile.AccountType.STAFF, "staff"]:
        name = f"{first} {last}"
        nip = f"198{0 + (val % 10):02d}{1 + (val % 12):02d}{1 + (val % 28):02d}{2015 + (val % 8):02d}{1 + (val % 2)}{201 + (val % 50)}"
        return name, nip
    else:
        name = f"{first} {last}"
        prefix = "08" if "fk" in str(email) else ("04" if "fh" in str(email) else ("07" if "feb" in str(email) else "08"))
        nim = f"{prefix}{20 + (val % 5):02d}11{1 + (val % 3)}3{val % 1000:03d}"
        return name, nim


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

    # Dynamic or synthetic full_name and nim_nip
    full_name = str(row.get("full_name") or "").strip()
    nim_nip = str(row.get("nim_nip") or "").strip()
    if not full_name or not nim_nip:
        gen_name, gen_id = generate_synthetic_identity_details(email, username, account_type)
        if not full_name:
            full_name = gen_name
        if not nim_nip:
            nim_nip = gen_id

    profile, _ = IdentityProfile.objects.get_or_create(
        identity_hash=identity_hash,
        defaults={
            "masked_email": mask_email(email),
            "masked_username": mask_username(username),
            "full_name": full_name,
            "nim_nip": nim_nip,
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
    if not profile.full_name or profile.full_name == "-":
        profile.full_name = full_name
    if not profile.nim_nip or profile.nim_nip == "-":
        profile.nim_nip = nim_nip
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
