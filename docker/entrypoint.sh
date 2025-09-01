#!/usr/bin/env bash
set -e

# Optional: collect static at runtime (uncomment if you prefer runtime collection)
# echo "Collecting static files..."
# python manage.py collectstatic --noinput --settings=ankavidange.settings_production

echo "Running Django migrations..."
python manage.py migrate --settings=ankavidange.settings_production

echo "Starting gunicorn..."
exec gunicorn ankavidange.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3

python manage.py collectstatic --noinput --settings=ankavidange.settings_production && \
python manage.py migrate --settings=ankavidange.settings_production