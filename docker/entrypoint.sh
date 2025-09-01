#!/usr/bin/env bash
set -e

echo "Running Django migrations..."
python manage.py migrate --settings=ankavidange.settings_production

echo "Starting gunicorn..."
exec gunicorn ankavidange.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3