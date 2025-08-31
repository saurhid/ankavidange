from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
import os

User = get_user_model()

class Command(BaseCommand):
    help = 'Setup admin user and initial data for production deployment'

    def add_arguments(self, parser):
        parser.add_argument(
            '--phone',
            type=str,
            help='Admin phone number',
            default=os.environ.get('ADMIN_PHONE', '+22376219484')
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Admin password',
            default=os.environ.get('ADMIN_PASSWORD', 'admin123')
        )
        parser.add_argument(
            '--email',
            type=str,
            help='Admin email',
            default=os.environ.get('ADMIN_EMAIL', 'admin@ankavidange.com')
        )
        parser.add_argument(
            '--first-name',
            type=str,
            help='Admin first name',
            default='Admin'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            help='Admin last name',
            default='System'
        )

    def handle(self, *args, **options):
        with transaction.atomic():
            # Create superuser if it doesn't exist
            phone_number = options['phone']
            
            if User.objects.filter(phone_number=phone_number).exists():
                self.stdout.write(
                    self.style.WARNING(f'Admin user with phone {phone_number} already exists')
                )
                return

            try:
                admin_user = User.objects.create_superuser(
                    phone_number=phone_number,
                    password=options['password'],
                    email=options['email'],
                    first_name=options['first_name'],
                    last_name=options['last_name'],
                    role=User.Role.ADMIN,
                    is_active=True,
                    is_staff=True,
                    is_superuser=True,
                    date_joined=timezone.now()
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully created admin user: {admin_user.phone_number}')
                )
                
                # Create initial centers if needed
                self.create_initial_centers()
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error creating admin user: {str(e)}')
                )
                raise

    def create_initial_centers(self):
        """Create initial vidange centers if they don't exist"""
        try:
            from ankavidangeapp.models import CentreVidange
            from django.contrib.gis.geos import Point
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Cannot import models for centers: {e}'))
            return

        centers_data = [
            {
                'nom': 'Centre Abidjan Nord',
                'position': Point(-4.0083, 5.3364),  # Abidjan approx
                'actif': True,
            },
            {
                'nom': 'Centre Abidjan Sud',
                'position': Point(-4.0267, 5.3097),
                'actif': True,
            },
        ]

        for payload in centers_data:
            obj, created = CentreVidange.objects.get_or_create(
                nom=payload['nom'],
                defaults=payload,
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created center: {obj.nom}'))
            else:
                # ensure fields updated if previously existed without position/actif
                changed = False
                if payload.get('position') and not obj.position:
                    obj.position = payload['position']
                    changed = True
                if payload.get('actif') and not obj.actif:
                    obj.actif = True
                    changed = True
                if changed:
                    obj.save(update_fields=['position', 'actif'])
                    self.stdout.write(self.style.WARNING(f'Updated existing center: {obj.nom}'))
