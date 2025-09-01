# Deploying Ankavidange (Django) on an Ubuntu Server (public IP, no Docker)

This guide sets up your app with:
- Gunicorn (systemd) as the app server
- Nginx as reverse proxy
- PostgreSQL + PostGIS
- TLS via Let’s Encrypt (optional, if you have a domain)

Paths used:
- App root: /srv/ankavidange
- Virtualenv: /srv/ankavidange/venv
- System user: ankav
- Gunicorn socket/port: 127.0.0.1:8000

Adjust names/paths as you like.

---

## 0) Prerequisites
- Ubuntu 22.04+ server with public IP
- SSH access with sudo
- Optional: a domain pointing to your server IP

## 1) System packages
```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install python3-pip python3-venv build-essential gcc \
  gdal-bin libgdal-dev libgeos-dev proj-bin libproj-dev \
  postgresql postgresql-contrib postgis postgresql-14-postgis-3 \
  nginx ufw
```

## 2) Database (PostgreSQL + PostGIS)
```bash
sudo -u postgres psql
CREATE DATABASE ankavidange;
CREATE USER ankavidange_user WITH PASSWORD 'change-this-strong-password';
GRANT ALL PRIVILEGES ON DATABASE ankavidange TO ankavidange_user;
\c ankavidange
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;
\q
```
Your DATABASE_URL becomes:
```
postgres://ankavidange_user:change-this-strong-password@127.0.0.1:5432/ankavidange
```

## 3) Application setup
```bash
sudo mkdir -p /srv/ankavidange && sudo chown $USER:$USER /srv/ankavidange
cd /srv/ankavidange
# Clone your repository
# git clone <your-repo-url> .

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Create /srv/ankavidange/.env with production values:
```
DJANGO_SETTINGS_MODULE=ankavidange.settings_production
SECRET_KEY=<your-strong-secret>
DEBUG=False
DATABASE_URL=postgres://ankavidange_user:change-this-strong-password@127.0.0.1:5432/ankavidange
# If you have a domain, set it here so the app adds it to hosts/CSRF
PUBLIC_HOST=https://your-domain.com
DJANGO_LOG_LEVEL=INFO
```

Migrate and collect static:
```bash
source /srv/ankavidange/venv/bin/activate
cd /srv/ankavidange
python manage.py migrate --settings=ankavidange.settings_production
python manage.py collectstatic --noinput --settings=ankavidange.settings_production
```

## 4) System user (optional but recommended)
```bash
sudo useradd --system --shell /bin/false --home /srv/ankavidange ankav
sudo chown -R ankav:ankav /srv/ankavidange
```

## 5) Gunicorn (systemd)
Create the service file:
```bash
sudo tee /etc/systemd/system/gunicorn.service >/dev/null << 'EOF'
[Unit]
Description=Gunicorn for ankavidange
After=network.target

[Service]
User=ankav
Group=www-data
WorkingDirectory=/srv/ankavidange
EnvironmentFile=/srv/ankavidange/.env
ExecStart=/srv/ankavidange/venv/bin/gunicorn ankavidange.wsgi:application \
  --bind 127.0.0.1:8000 --workers 3 --timeout 120 --log-level info
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now gunicorn
sudo systemctl status gunicorn --no-pager
```

## 6) Nginx
Use the example config from this repo: deploy/server/nginx.example.conf
```bash
sudo cp /srv/ankavidange/deploy/server/nginx.example.conf /etc/nginx/sites-available/ankavidange
sudo sed -i "s/server_name PLACEHOLDER_DOMAIN/server_name your-domain.com your.server.ip/" /etc/nginx/sites-available/ankavidange
sudo ln -s /etc/nginx/sites-available/ankavidange /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 7) Firewall
```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable
sudo ufw status
```

## 8) HTTPS (if domain)
```bash
sudo apt -y install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

## 9) Logs & troubleshooting
- Gunicorn: `sudo journalctl -u gunicorn -f`
- Nginx access/error: `/var/log/nginx/{access,error}.log`
- Django app logs printed to stdout (via systemd)

## Notes about settings
- Ensure `ALLOWED_HOSTS` contains your IP or domain. If you set `PUBLIC_HOST` in `.env`, we recommend adding a small hook in settings to auto-include it (see below if not already present).
- Ensure `CSRF_TRUSTED_ORIGINS` includes your exact origin (e.g., `https://your-domain.com`).
- `ENGINE` is `django.contrib.gis.db.backends.postgis`. PostGIS extensions must be present.

If needed, you can modify `ankavidange/ankavidange/settings_production.py` to read `PUBLIC_HOST` and add it to `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`.
