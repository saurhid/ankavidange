#!/usr/bin/env python
"""
Deployment script for Railway
Handles database migrations, static files, and admin setup
"""
import os
import sys
import django
from django.core.management import execute_from_command_line

def setup_django():
    """Setup Django environment"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ankavidange.settings_production')
    django.setup()

def run_migrations():
    """Run database migrations"""
    print("Running database migrations...")
    execute_from_command_line(['manage.py', 'migrate', '--noinput'])
    print("✓ Migrations completed")

def collect_static():
    """Collect static files"""
    print("Collecting static files...")
    execute_from_command_line(['manage.py', 'collectstatic', '--noinput'])
    print("✓ Static files collected")

def setup_admin():
    """Setup admin user"""
    print("Setting up admin user...")
    try:
        execute_from_command_line(['manage.py', 'setup_admin'])
        print("✓ Admin setup completed")
    except Exception as e:
        print(f"⚠ Admin setup warning: {e}")

def main():
    """Main deployment function"""
    setup_django()
    
    print("🚀 Starting Railway deployment setup...")
    
    try:
        run_migrations()
        collect_static()
        setup_admin()
        print("✅ Deployment setup completed successfully!")
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
