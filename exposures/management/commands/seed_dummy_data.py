from django.core.management.base import BaseCommand

from exposures.services import (
    DEFAULT_DUMMY_ROWS,
    ensure_roles_and_demo_users,
    import_rows,
    reset_exposure_data,
    seed_domain_assets,
)


class Command(BaseCommand):
    help = "Seed synthetic UNAIR exposure data for local development and demo."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true")
        parser.add_argument("--create-demo-users", action="store_true")

    def handle(self, *args, **options):
        if options["reset"]:
            reset_exposure_data()
        seed_domain_assets()
        ensure_roles_and_demo_users(create_demo_users=options["create_demo_users"])
        stats = import_rows(DEFAULT_DUMMY_ROWS, source_label="synthetic-stealer-sample")
        self.stdout.write(
            self.style.SUCCESS(
                "Seed complete: {imported} imported, {duplicates} duplicates, {skipped} skipped, {errors} errors".format(
                    imported=stats.imported,
                    duplicates=stats.duplicates,
                    skipped=stats.skipped_non_unair,
                    errors=stats.errors,
                )
            )
        )
