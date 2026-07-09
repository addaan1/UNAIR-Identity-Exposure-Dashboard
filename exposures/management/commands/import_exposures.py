from django.core.management.base import BaseCommand

from exposures.services import import_csv, reset_exposure_data, seed_domain_assets


class Command(BaseCommand):
    help = "Import authorized exposure CSV data with masking and risk scoring."

    def add_arguments(self, parser):
        parser.add_argument("csv_path")
        parser.add_argument("--source", default="uploaded")
        parser.add_argument("--reset", action="store_true")

    def handle(self, *args, **options):
        if options["reset"]:
            reset_exposure_data()
        seed_domain_assets()
        stats = import_csv(options["csv_path"], source_label=options["source"])
        self.stdout.write(
            self.style.SUCCESS(
                "Imported {imported}; duplicates {duplicates}; skipped {skipped}; errors {errors}".format(
                    imported=stats.imported,
                    duplicates=stats.duplicates,
                    skipped=stats.skipped_non_unair,
                    errors=stats.errors,
                )
            )
        )
