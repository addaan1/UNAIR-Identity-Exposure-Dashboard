from django.core.management.base import BaseCommand

from exposures.services import ensure_roles_and_demo_users


class Command(BaseCommand):
    help = "Create dashboard auth groups and optional demo users."

    def add_arguments(self, parser):
        parser.add_argument("--create-demo-users", action="store_true")

    def handle(self, *args, **options):
        ensure_roles_and_demo_users(create_demo_users=options["create_demo_users"])
        self.stdout.write(self.style.SUCCESS("Roles are ready"))
