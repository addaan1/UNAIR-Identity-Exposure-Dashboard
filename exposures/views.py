import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, Max, Q
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import AuditLog, DomainAsset, IdentityProfile, RawExposure, RemediationAction


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
    return filters, {"q": q, "level": level, "status": status}


@login_required
def overview(request):
    total_exposures = RawExposure.objects.count()
    high_risk_count = RawExposure.objects.filter(
        risk_score__level__in=["high", "critical"]
    ).count()
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
        .order_by("-risk_score__score", "-observed_at")[:8]
    )
    context = {
        "kpis": {
            "total_exposures": total_exposures,
            "unique_identities": IdentityProfile.objects.count(),
            "impacted_domains": RawExposure.objects.values("normalized_domain").distinct().count(),
            "high_risk_count": high_risk_count,
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
    write_audit(request, "view_identity_exposure", metadata=active_filters)
    return render(
        request,
        "exposures/identity_exposure.html",
        {"profiles": profiles, "filters": active_filters},
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
