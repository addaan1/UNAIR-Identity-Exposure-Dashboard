from django.core.management.base import BaseCommand

from exposures.models import RawExposure, RiskScore
from exposures.services import calculate_risk_score


class Command(BaseCommand):
    help = "Recompute risk scores for all imported exposures."

    def handle(self, *args, **options):
        count = 0
        for exposure in RawExposure.objects.select_related("domain_asset", "identity_profile"):
            score, level, factors = calculate_risk_score(exposure)
            RiskScore.objects.update_or_create(
                exposure=exposure,
                defaults={"score": score, "level": level, "factors": factors},
            )
            count += 1
        self.stdout.write(self.style.SUCCESS(f"Recomputed {count} risk scores"))
