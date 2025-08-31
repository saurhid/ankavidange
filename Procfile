web: python manage.py migrate --settings=ankavidange.settings_production && gunicorn --bind 0.0.0.0:$PORT ankavidange.wsgi:application
release: python manage.py migrate --settings=ankavidange.settings_production && python manage.py collectstatic --noinput --settings=ankavidange.settings_production
