# Ubuntu Deployment Guide (Nginx + Gunicorn + PostGIS)

This guide deploys the Django app `ankavidange` on Ubuntu with Nginx, Gunicorn, PostgreSQL + PostGIS, and GeoDjango dependencies.

Tested on Ubuntu 22.04 LTS.

## 1) Install System Packages

```bash
sudo apt update && sudo apt -y upgrade
# Core build tools
sudo apt -y install python3-pip python3-venv python3-dev build-essential \
  libpq-dev \
  gdal-bin libgdal-dev libgeos-dev libproj-dev \
  postgresql postgresql-contrib postgis \
  nginx

# Check GDAL version
gdalinfo --version
```

## 2) Database Setup (PostgreSQL + PostGIS)

```bash
sudo -u postgres psql <<'SQL'
CREATE DATABASE vidange;
CREATE USER ankavidange_user WITH PASSWORD 'StrongPasswordHere';
GRANT ALL PRIVILEGES ON DATABASE vidange TO ankavidange_user;
\c vidange
CREATE EXTENSION IF NOT EXISTS postgis;
SQL
```

Record your connection string:
```
postgresql://ankavidange_user:StrongPasswordHere@localhost:5432/vidange
```

## 3) Create App Directory Structure

```bash
sudo mkdir -p /opt/ankavidange
sudo mkdir -p /opt/ankavidange/deploy /opt/ankavidange/media
sudo chown -R $USER:www-data /opt/ankavidange
```

## 4) Copy Project and Create Virtualenv

Place your repository on the server (git clone or scp). Example using git:
```bash
cd /opt/ankavidange
git clone <YOUR_REPO_URL> src
cd /opt/ankavidange
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r src/requirements.txt
```

If you didn't use git, copy the project contents so that `manage.py` is at `/opt/ankavidange/src/manage.py`.

## 5) Environment Variables

Create an env file from the template:
```bash
cp /opt/ankavidange/src/.env.example /opt/ankavidange/.env
nano /opt/ankavidange/.env
```
Update values:
- SECRET_KEY (generate a strong key)
- ALLOWED_HOSTS (your domain or server IP)
- CSRF_TRUSTED_ORIGINS (with scheme, e.g., https://your.domain)
- DATABASE_URL (use the connection string created above)
- DEBUG=False

Optionally export settings in current shell for manage.py:
```bash
export DJANGO_SETTINGS_MODULE=ankavidange.settings_production
```

## 6) Django Setup (Migrate, Collectstatic, Create Admin)

```bash
cd /opt/ankavidange/src
source /opt/ankavidange/venv/bin/activate
python manage.py migrate --settings=ankavidange.settings_production
python manage.py collectstatic --noinput --settings=ankavidange.settings_production
# Optional: bootstrap admin user via provided command
python manage.py setup_admin --settings=ankavidange.settings_production
```

Static files will be collected to `/opt/ankavidange/staticfiles` per `ankavidange/settings_production.py`.

## 7) Gunicorn (systemd)

Install service file and config:
```bash
sudo cp /opt/ankavidange/src/deploy/gunicorn.conf.py /opt/ankavidange/deploy/gunicorn.conf.py
sudo cp /opt/ankavidange/src/deploy/systemd/ankavidange.service /etc/systemd/system/ankavidange.service
```

Edit the service if paths differ:
- WorkingDirectory=/opt/ankavidange/src (if you kept repo under `src`)
- PATH=/opt/ankavidange/venv/bin
- EnvironmentFile=/opt/ankavidange/.env

Then enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ankavidange
sudo systemctl start ankavidange
sudo systemctl status ankavidange --no-pager -l
```

Logs:
```bash
journalctl -u ankavidange -f
```

## 8) Nginx

```bash
sudo cp /opt/ankavidange/src/deploy/nginx/ankavidange.conf /etc/nginx/sites-available/ankavidange
sudo ln -s /etc/nginx/sites-available/ankavidange /etc/nginx/sites-enabled/ankavidange

# Adjust server_name, static/media aliases if your paths differ
sudo nginx -t
sudo systemctl reload nginx
```

If you plan to use HTTPS with a domain, install Certbot:
```bash
sudo apt -y install certbot python3-certbot-nginx
sudo certbot --nginx -d your.domain.com
```

## 9) Firewall (UFW)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## 10) Health Checks and Maintenance

- App reachable at http://your.domain.com
- Static served by Nginx from `/opt/ankavidange/staticfiles/`
- Media files at `/opt/ankavidange/media/` (upload paths must write here)
- Restart app after code updates:
  ```bash
  cd /opt/ankavidange/src
  git pull
  source /opt/ankavidange/venv/bin/activate
  pip install -r requirements.txt
  python manage.py migrate --settings=ankavidange.settings_production
  python manage.py collectstatic --noinput --settings=ankavidange.settings_production
  sudo systemctl restart ankavidange
  ```

## 11) Notes Specific to GeoDjango

- Ensure `gdalinfo --version` works; otherwise install proper GDAL packages.
- The Django DB engine in production is explicitly set to `django.contrib.gis.db.backends.postgis`.
- PostGIS extension must be enabled in the database.

## 12) Troubleshooting

- 502/Bad Gateway: Check `systemctl status ankavidange` and `journalctl -u ankavidange -f`.
- Database auth errors: verify `DATABASE_URL` and PostgreSQL roles.
- Static not loading: verify `collectstatic` output and Nginx `alias` paths.
- GeoDjango import errors: confirm `gdal-bin libgdal-dev libgeos-dev libproj-dev` installed.
