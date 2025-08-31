# Railway Deployment Guide for Allo-Vidange

This guide covers deploying the Allo-Vidange Django application to Railway with PostgreSQL and GeoDjango support.

## Prerequisites

- Railway account
- Git repository with your code
- PostgreSQL database service on Railway

## 1. Railway Setup

### Create New Project
1. Go to [Railway](https://railway.app)
2. Click "New Project"
3. Choose "Deploy from GitHub repo"
4. Select your repository

### Add PostgreSQL Database
1. In your Railway project dashboard
2. Click "New Service"
3. Choose "Database" → "PostgreSQL"
4. Railway will automatically create a PostgreSQL instance

## 2. Environment Variables

Set these environment variables in Railway:

```bash
# Required Variables
SECRET_KEY=your-super-secret-key-here
DEBUG=False
DJANGO_SETTINGS_MODULE=ankavidange.settings_production

# Admin Setup (Optional - defaults provided)
ADMIN_PHONE=+225XXXXXXXX
ADMIN_PASSWORD=your-secure-password
ADMIN_EMAIL=admin@ankavidange.com

# Database (Automatically set by Railway)
DATABASE_URL=postgresql://...
```

### Generate Secret Key
```python
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
```

## 3. Deployment Configuration Files

The following files are already configured for Railway:

- `requirements.txt` - Python dependencies including GeoDjango
- `nixpacks.toml` - Build configuration with GDAL/GEOS
- `Procfile` - Process definitions
- `railway.json` - Railway-specific configuration
- `settings_production.py` - Production Django settings

## 4. GeoDjango Dependencies

Railway automatically installs these through nixpacks.toml:
- GDAL (Geospatial Data Abstraction Library)
- GEOS (Geometry Engine Open Source)
- PROJ (Cartographic Projections Library)
- PostGIS (PostgreSQL extension)

## 5. Deployment Process

### Automatic Deployment
Railway will automatically:
1. Install Python dependencies
2. Install GeoDjango system packages
3. Run database migrations
4. Collect static files
5. Start the application with Gunicorn

### Manual Commands (if needed)
```bash
# Run migrations
python manage.py migrate --settings=ankavidange.settings_production

# Create admin user
python manage.py setup_admin --settings=ankavidange.settings_production

# Collect static files
python manage.py collectstatic --noinput --settings=ankavidange.settings_production
```

## 6. Post-Deployment Setup

### Create Admin User
The deployment automatically creates an admin user with:
- Phone: Value from `ADMIN_PHONE` env var
- Password: Value from `ADMIN_PASSWORD` env var
- Email: Value from `ADMIN_EMAIL` env var

### Access Admin Panel
Visit: `https://your-app.railway.app/admin/`

## 7. Database Configuration

### PostGIS Extension
The PostgreSQL database includes PostGIS extension for geographic data support.

### Connection Pooling
Database connections are configured with:
- Connection max age: 600 seconds
- Health checks enabled

## 8. Static Files

Static files are handled by WhiteNoise middleware:
- Automatically compressed
- Served with proper caching headers
- No separate CDN required

## 9. Security Features

Production settings include:
- HTTPS redirect (when not in debug mode)
- HSTS headers
- Secure cookies
- XSS protection
- Content type sniffing protection

## 10. Monitoring and Logs

### View Logs
```bash
# In Railway dashboard
Go to your service → Logs tab
```

### Health Checks
The application includes basic health monitoring through Railway's built-in system.

## 11. Custom Domain (Optional)

1. In Railway dashboard → Settings → Domains
2. Add your custom domain
3. Update `RAILWAY_STATIC_URL` environment variable
4. Configure DNS records as instructed

## 12. Troubleshooting

### Common Issues

**GeoDjango Import Errors:**
- Ensure nixpacks.toml includes all required packages
- Check GDAL/GEOS library paths in logs

**Database Connection Issues:**
- Verify DATABASE_URL is set correctly
- Check PostgreSQL service is running

**Static Files Not Loading:**
- Run `collectstatic` command manually
- Check STATIC_ROOT configuration

**Admin User Creation Failed:**
- Check ADMIN_PHONE format (+225XXXXXXXX)
- Ensure phone number is unique
- Verify all required fields are provided

### Debug Commands
```bash
# Check database connection
python manage.py dbshell --settings=ankavidange.settings_production

# Validate models
python manage.py check --settings=ankavidange.settings_production

# Create superuser manually
python manage.py createsuperuser --settings=ankavidange.settings_production
```

## 13. Scaling

Railway automatically handles:
- Horizontal scaling based on traffic
- Database connection pooling
- Static file caching

## 14. Backup Strategy

### Database Backups
Railway PostgreSQL includes automatic daily backups.

### Manual Backup
```bash
# Export data
python manage.py dumpdata --settings=ankavidange.settings_production > backup.json

# Import data
python manage.py loaddata backup.json --settings=ankavidange.settings_production
```

## Support

For issues specific to Railway deployment, check:
- Railway documentation
- Railway Discord community
- Project logs in Railway dashboard
