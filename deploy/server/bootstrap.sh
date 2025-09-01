#!/usr/bin/env bash
# Automated setup for Ankavidange on Ubuntu (no Docker)
# Usage: sudo bash bootstrap.sh <domain_or_ip> <db_name> <db_user> <db_password>
set -euo pipefail

DOMAIN_OR_IP=${1:-your.server.ip}
DB_NAME=${2:-ankavidange}
DB_USER=${3:-ankavidange_user}
DB_PASS=${4:-change-me}
APP_USER=ankav
APP_ROOT=/srv/ankavidange
PY=python3
DOLLAR='$'

echo "[1/8] Update system and install packages"
apt update && apt -y upgrade
apt -y install ${PY}-pip ${PY}-venv build-essential gcc \
  gdal-bin libgdal-dev libgeos-dev proj-bin libproj-dev \
  postgresql postgresql-contrib postgis postgresql-14-postgis-3 \
  nginx ufw git

echo "[2/8] Create Postgres DB and enable PostGIS"
# Create role if missing
role_exists=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'") || true
if [ "${role_exists}" != "1" ]; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS}';"
fi

# Create database if missing and set owner
db_exists=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'") || true
if [ "${db_exists}" != "1" ]; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"${DB_NAME}\" OWNER \"${DB_USER}\";"
fi

# Enable PostGIS extensions
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB_NAME}" -c "CREATE EXTENSION IF NOT EXISTS postgis;"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB_NAME}" -c "CREATE EXTENSION IF NOT EXISTS postgis_topology;"

DB_URL="postgres://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}"

echo "[3/8] Create app directory and venv"
mkdir -p ${APP_ROOT}
chown -R $SUDO_USER:$SUDO_USER ${APP_ROOT}
cd ${APP_ROOT}

if [ ! -d .git ]; then
  echo "Clone your repo into ${APP_ROOT} (skip if already cloned)"
  echo "  git clone <your-repo-url> ${APP_ROOT}"
fi

sudo -u $SUDO_USER ${PY} -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
fi

echo "[4/8] Create .env"
cat >/srv/ankavidange/.env <<EOF
DJANGO_SETTINGS_MODULE=ankavidange.settings_production
SECRET_KEY=$(openssl rand -hex 32)
DEBUG=False
DATABASE_URL=${DB_URL}
PUBLIC_HOST=http://${DOMAIN_OR_IP}
DJANGO_LOG_LEVEL=INFO
EOF

echo "[5/8] Migrate and collectstatic"
source ${APP_ROOT}/venv/bin/activate
cd ${APP_ROOT}
python manage.py migrate --settings=ankavidange.settings_production
python manage.py collectstatic --noinput --settings=ankavidange.settings_production

echo "[6/8] Create system user and permissions"
if ! id -u ${APP_USER} >/dev/null 2>&1; then
  useradd --system --shell /bin/false --home ${APP_ROOT} ${APP_USER}
fi
chown -R ${APP_USER}:www-data ${APP_ROOT}

echo "[7/8] Install and start gunicorn service"
cat >/etc/systemd/system/gunicorn.service <<SERVICE
[Unit]
Description=Gunicorn for ankavidange
After=network.target

[Service]
User=${APP_USER}
Group=www-data
WorkingDirectory=${APP_ROOT}
EnvironmentFile=${APP_ROOT}/.env
ExecStart=${APP_ROOT}/venv/bin/gunicorn ankavidange.wsgi:application \
  --bind 127.0.0.1:8000 --workers 3 --timeout 120 --log-level info
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now gunicorn
systemctl status gunicorn --no-pager || true

echo "[8/8] Configure Nginx"
cat >/etc/nginx/sites-available/ankavidange <<NGINX
server {
    listen 80;
    server_name ${DOMAIN_OR_IP};
    client_max_body_size 20m;

    location /static/ { alias ${APP_ROOT}/ankavidangeapp/static/; }
    location /media/  { alias ${APP_ROOT}/media/; }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/ankavidange /etc/nginx/sites-enabled/ankavidange
nginx -t
systemctl reload nginx

ufw allow OpenSSH || true
ufw allow 'Nginx Full' || true
yes | ufw enable || true

echo "Done. Visit: http://${DOMAIN_OR_IP}/"
