from django.urls import path

from . import views


urlpatterns = [
    path("", views.overview, name="overview"),
    path("domains/", views.domain_risk, name="domain_risk"),
    path("identities/", views.identity_exposure, name="identity_exposure"),
    path("high-risk/", views.high_risk, name="high_risk"),
    path("remediation/", views.remediation, name="remediation"),
    path("export/exposures.csv", views.export_exposures_csv, name="export_exposures_csv"),
]
