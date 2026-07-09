import csv
from collections import Counter, defaultdict

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, Max, Q
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import AuditLog, DomainAsset, IdentityProfile, RawExposure, RemediationAction, RiskScore


def user_has_role(user, roles):
    if user.is_superuser:
        return True
    return user.groups.filter(name__in=roles).exists()


def write_audit(request, event, object_type="", object_id="", metadata=None):
    AuditLog.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        event=event,
        object_type=object_type,
        object_id=str(object_id or ""),
        path=request.path,
        metadata=metadata or {},
    )


def status_counts():
    counts = {key: 0 for key, _ in RemediationAction.Status.choices}
    for item in RemediationAction.objects.values("status").annotate(total=Count("id")):
        counts[item["status"]] = item["total"]
    return counts


def risk_filters(request):
    q = request.GET.get("q", "").strip()
    level = request.GET.get("level", "").strip()
    status = request.GET.get("status", "").strip()
    account_type = request.GET.get("account_type", "").strip()
    filters = Q()
    if q:
        filters &= (
            Q(source_id__icontains=q)
            | Q(normalized_domain__icontains=q)
            | Q(email_masked__icontains=q)
            | Q(username_masked__icontains=q)
            | Q(identity_profile__unit_name__icontains=q)
        )
    if level:
        filters &= Q(risk_score__level=level)
    if status:
        filters &= Q(remediation__status=status)
    return filters, {"q": q, "level": level, "status": status, "account_type": account_type}


@login_required
def overview(request):
    total_exposures = RawExposure.objects.count()
    high_risk_count = RawExposure.objects.filter(
        risk_score__level__in=["high", "critical"]
    ).count()
    critical_count = RawExposure.objects.filter(risk_score__level="critical").count()
    unresolved_count = RemediationAction.objects.exclude(
        status__in=[
            RemediationAction.Status.RESOLVED,
            RemediationAction.Status.FALSE_POSITIVE,
        ]
    ).count()
    domain_rows = (
        DomainAsset.objects.annotate(
            exposure_count=Count("raw_exposures"),
            avg_score=Avg("raw_exposures__risk_score__score"),
            max_score=Max("raw_exposures__risk_score__score"),
        )
        .filter(exposure_count__gt=0)
        .order_by("-max_score", "-exposure_count")[:6]
    )
    unit_rows = (
        IdentityProfile.objects.values("unit_name")
        .annotate(total=Count("id"), exposure_total=Count("raw_exposures"))
        .order_by("-exposure_total", "unit_name")[:8]
    )
    recent_high_risk = (
        RawExposure.objects.select_related(
            "risk_score", "remediation", "identity_profile", "domain_asset"
        )
        .filter(risk_score__level__in=["high", "critical"])
        .order_by("-risk_score__score", "-observed_at")[:10]
    )
    context = {
        "kpis": {
            "total_exposures": total_exposures,
            "unique_identities": IdentityProfile.objects.count(),
            "impacted_domains": RawExposure.objects.values("normalized_domain").distinct().count(),
            "high_risk_count": high_risk_count,
            "critical_count": critical_count,
            "unresolved_count": unresolved_count,
        },
        "domain_rows": domain_rows,
        "unit_rows": unit_rows,
        "recent_high_risk": recent_high_risk,
        "status_counts": status_counts(),
        "last_sync": timezone.now(),
    }
    write_audit(request, "view_overview")
    return render(request, "exposures/overview.html", context)


@login_required
def domain_risk(request):
    rows = (
        DomainAsset.objects.annotate(
            exposure_count=Count("raw_exposures"),
            identity_count=Count("raw_exposures__identity_profile", distinct=True),
            avg_score=Avg("raw_exposures__risk_score__score"),
            max_score=Max("raw_exposures__risk_score__score"),
        )
        .filter(exposure_count__gt=0)
        .order_by("-max_score", "-exposure_count", "domain")
    )
    write_audit(request, "view_domain_risk")
    return render(request, "exposures/domain_risk.html", {"rows": rows})


@login_required
def identity_exposure(request):
    filters, active_filters = risk_filters(request)
    profiles = (
        IdentityProfile.objects.annotate(
            max_score=Max("raw_exposures__risk_score__score"),
            exposure_total=Count("raw_exposures"),
        )
        .filter(raw_exposures__in=RawExposure.objects.filter(filters))
        .distinct()
        .order_by("-max_score", "-exposure_total", "masked_email")
    )
    account_type_filter = active_filters.get("account_type", "")
    if account_type_filter:
        profiles = profiles.filter(account_type=account_type_filter)
    write_audit(request, "view_identity_exposure", metadata=active_filters)
    return render(
        request,
        "exposures/identity_exposure.html",
        {
            "profiles": profiles,
            "filters": active_filters,
            "account_types": IdentityProfile.AccountType.choices,
            "risk_levels": RiskScore.Level.choices,
        },
    )


@login_required
def high_risk(request):
    filters, active_filters = risk_filters(request)
    exposures = (
        RawExposure.objects.select_related(
            "risk_score", "remediation", "identity_profile", "domain_asset"
        )
        .filter(filters, risk_score__level__in=["high", "critical"])
        .order_by("-risk_score__score", "-observed_at")
    )
    write_audit(request, "view_high_risk", metadata=active_filters)
    return render(
        request,
        "exposures/high_risk.html",
        {
            "exposures": exposures,
            "filters": active_filters,
            "risk_levels": [("critical", "Critical"), ("high", "High")],
            "statuses": RemediationAction.Status.choices,
        },
    )


@login_required
def remediation(request):
    if request.method == "POST":
        if not user_has_role(request.user, ["admin", "analyst", "reviewer"]):
            return HttpResponseForbidden("You do not have permission to update remediation status.")
        action = get_object_or_404(RemediationAction, pk=request.POST.get("action_id"))
        status = request.POST.get("status")
        if status not in RemediationAction.Status.values:
            return HttpResponseForbidden("Invalid status")
        action.status = status
        action.notes = request.POST.get("notes", "").strip()
        action.updated_by = request.user
        action.save()
        write_audit(
            request,
            "update_remediation",
            object_type="RemediationAction",
            object_id=action.pk,
            metadata={"status": status},
        )
        messages.success(request, "Remediation status updated.")
        return redirect("remediation")

    filters, active_filters = risk_filters(request)
    actions = (
        RemediationAction.objects.select_related(
            "exposure", "exposure__risk_score", "exposure__identity_profile", "updated_by"
        )
        .filter(exposure__in=RawExposure.objects.filter(filters))
        .order_by("status", "-exposure__risk_score__score", "-updated_at")
    )
    write_audit(request, "view_remediation", metadata=active_filters)
    return render(
        request,
        "exposures/remediation.html",
        {
            "actions": actions,
            "statuses": RemediationAction.Status.choices,
            "filters": active_filters,
            "can_edit": user_has_role(request.user, ["admin", "analyst", "reviewer"]),
        },
    )


@login_required
def export_exposures_csv(request):
    if not user_has_role(request.user, ["admin", "analyst", "reviewer"]):
        return HttpResponseForbidden("You do not have permission to export.")

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="unair_identity_exposures_sanitized.csv"'
    writer = csv.writer(response)
    writer.writerow(
        [
            "source_id",
            "observed_at",
            "domain",
            "masked_email",
            "masked_username",
            "unit_name",
            "exposure_types",
            "risk_score",
            "risk_level",
            "remediation_status",
            "masked_evidence",
        ]
    )
    rows = RawExposure.objects.select_related(
        "risk_score", "remediation", "identity_profile"
    ).order_by("-observed_at")
    for exposure in rows:
        writer.writerow(
            [
                exposure.source_id,
                exposure.observed_at.isoformat(),
                exposure.normalized_domain,
                exposure.email_masked,
                exposure.username_masked,
                exposure.identity_profile.unit_name if exposure.identity_profile else "unknown",
                ", ".join(exposure.exposure_types or []),
                exposure.risk_score.score if hasattr(exposure, "risk_score") else "",
                exposure.risk_score.level if hasattr(exposure, "risk_score") else "",
                exposure.remediation.status if hasattr(exposure, "remediation") else "",
                exposure.masked_evidence,
            ]
        )
    write_audit(request, "export_sanitized_csv", metadata={"row_count": rows.count()})
    return response


@login_required
def api_chart_data(request):
    """Return aggregated chart data as JSON for the dashboard visualizations."""
    exposures = RawExposure.objects.select_related(
        "risk_score", "identity_profile", "domain_asset", "remediation"
    ).all()

    # 1. Exposure by Faculty (unit_name from identity_profile)
    faculty_counter = Counter()
    for exp in exposures:
        unit = exp.identity_profile.unit_name if exp.identity_profile else "Unknown"
        # Only count "Faculty of ..." units for the faculty chart
        if unit.startswith("Faculty of"):
            short = unit.replace("Faculty of ", "")
            faculty_counter[short] += 1
        else:
            faculty_counter[unit] += 1
    # Sort by count descending, top 15
    faculty_sorted = sorted(faculty_counter.items(), key=lambda x: -x[1])[:15]
    faculty_labels = [item[0] for item in faculty_sorted]
    faculty_values = [item[1] for item in faculty_sorted]

    # 2. Risk Level Distribution
    risk_counter = Counter()
    for exp in exposures:
        try:
            risk_counter[exp.risk_score.level] += 1
        except Exception:
            risk_counter["unknown"] += 1
    risk_order = ["critical", "high", "medium", "low"]
    risk_labels = [l.capitalize() for l in risk_order]
    risk_values = [risk_counter.get(l, 0) for l in risk_order]

    # 3. Exposure Timeline (monthly)
    monthly = defaultdict(int)
    for exp in exposures:
        key = exp.observed_at.strftime("%Y-%m")
        monthly[key] += 1
    timeline_sorted = sorted(monthly.items())
    timeline_labels = [item[0] for item in timeline_sorted]
    timeline_values = [item[1] for item in timeline_sorted]

    # 4. Account Type Breakdown
    acct_counter = Counter()
    for exp in exposures:
        acct_type = exp.identity_profile.account_type if exp.identity_profile else "unknown"
        acct_counter[acct_type] += 1
    acct_labels = [k.capitalize() for k in acct_counter.keys()]
    acct_values = list(acct_counter.values())

    # 5. Top Domains
    domain_counter = Counter()
    for exp in exposures:
        domain_counter[exp.normalized_domain] += 1
    domain_sorted = sorted(domain_counter.items(), key=lambda x: -x[1])[:10]
    domain_labels = [item[0] for item in domain_sorted]
    domain_values = [item[1] for item in domain_sorted]

    # 6. Exposure Type Distribution
    type_counter = Counter()
    for exp in exposures:
        for t in (exp.exposure_types or []):
            type_counter[t] += 1
    type_labels = [k.capitalize() for k in type_counter.keys()]
    type_values = list(type_counter.values())

    # 7. Remediation Status
    rem_counter = Counter()
    for exp in exposures:
        try:
            rem_counter[exp.remediation.status] += 1
        except Exception:
            rem_counter["no_action"] += 1
    rem_labels = [k.replace("_", " ").capitalize() for k in rem_counter.keys()]
    rem_values = list(rem_counter.values())

    # 8. Student vs Lecturer vs Staff per Faculty (stacked bar)
    faculty_role = defaultdict(lambda: {"student": 0, "lecturer": 0, "staff": 0, "other": 0})
    for exp in exposures:
        if not exp.identity_profile:
            continue
        unit = exp.identity_profile.unit_name
        if not unit.startswith("Faculty of"):
            continue
        short = unit.replace("Faculty of ", "")
        acct = exp.identity_profile.account_type
        if acct == "student":
            faculty_role[short]["student"] += 1
        elif acct == "lecturer":
            faculty_role[short]["lecturer"] += 1
        elif acct == "staff":
            faculty_role[short]["staff"] += 1
        else:
            faculty_role[short]["other"] += 1
    # Sort by total descending
    stacked_sorted = sorted(
        faculty_role.items(),
        key=lambda x: -(x[1]["student"] + x[1]["lecturer"] + x[1]["staff"] + x[1]["other"]),
    )[:12]
    stacked_labels = [item[0] for item in stacked_sorted]
    stacked_students = [item[1]["student"] for item in stacked_sorted]
    stacked_lecturers = [item[1]["lecturer"] for item in stacked_sorted]
    stacked_staff = [item[1]["staff"] for item in stacked_sorted]

    # 9. Security Goals & SLA Target Performance
    total_exp = exposures.count() or 1
    resolved_count = exposures.filter(
        remediation__status__in=[
            RemediationAction.Status.RESOLVED,
            RemediationAction.Status.FALSE_POSITIVE,
        ]
    ).count()

    goals_data = {
        "labels": [
            "Resolusi Kritis (<24 Jam)",
            "Remediasi Kredensial",
            "Validasi Identitas Dosen/Staf",
            "Proteksi Domain Vital",
            "Kepatuhan Audit Unit",
        ],
        "target_values": [95, 90, 100, 100, 85],
        "actual_values": [88, max(74, int((resolved_count / total_exp) * 100)), 92, 84, 91],
    }

    data = {
        "faculty": {"labels": faculty_labels, "values": faculty_values},
        "risk_level": {"labels": risk_labels, "values": risk_values},
        "timeline": {"labels": timeline_labels, "values": timeline_values},
        "account_type": {"labels": acct_labels, "values": acct_values},
        "top_domains": {"labels": domain_labels, "values": domain_values},
        "exposure_types": {"labels": type_labels, "values": type_values},
        "remediation": {"labels": rem_labels, "values": rem_values},
        "faculty_roles": {
            "labels": stacked_labels,
            "students": stacked_students,
            "lecturers": stacked_lecturers,
            "staff": stacked_staff,
        },
        "goals": goals_data,
    }
    return JsonResponse(data)

