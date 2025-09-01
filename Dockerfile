# syntax=docker/dockerfile:1

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=ankavidange.settings_production \
    PATH="/usr/local/bin:$PATH"

# Install system packages for GeoDjango and Postgres client
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc \
    gdal-bin libgdal-dev \
    proj-bin libproj-dev \
    libgeos-dev \
    postgresql-client \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first to leverage layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Copy project
COPY . /app

# Collect static at build time
RUN python manage.py collectstatic --noinput --settings=ankavidange.settings_production

# Entrypoint runs migrations then starts gunicorn
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

CMD ["/entrypoint.sh"]
