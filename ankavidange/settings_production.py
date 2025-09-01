"""
Production settings for DigitalOcean (or any VM) deployment behind Nginx
"""
import os
import dj_database_url
from pathlib import Path
from urllib.parse import urlparse
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-change-me-in-production')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Optional: service PORT (unused when using systemd + Nginx reverse proxy)
PORT = os.environ.get('PORT', '8000')

# Allowed hosts
ALLOWED_HOSTS = [
    '45.55.62.212',
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
]

# Add custom domain/host if provided via env
PUBLIC_HOST = os.environ.get('PUBLIC_HOST')  # e.g., https://example.com or example.com or server IP

def _normalize_host(url_or_host: str) -> tuple[str | None, str | None]:
    # returns (scheme, host)
    parsed = urlparse(url_or_host)
    host = (parsed.netloc or url_or_host.replace('https://', '').replace('http://', '')).strip('/')
    scheme = parsed.scheme or None
    if not host:
        return None, None
    return scheme, host

if PUBLIC_HOST:
    scheme, host = _normalize_host(PUBLIC_HOST)
    if host and host not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(host)

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.gis',
    'rest_framework',
    'rest_framework_gis',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_filters',
    'ankavidangeapp',
    'django_extensions',
    'widget_tweaks',
    'whitenoise.runserver_nostatic',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'ankavidangeapp.middleware.JWTAuthenticationMiddleware',
]

ROOT_URLCONF = 'ankavidange.urls'
AUTH_USER_MODEL = 'ankavidangeapp.User'

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'ankavidangeapp.backends.PhoneNumberBackend',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ankavidange.wsgi.application'

# Database configuration (PostgreSQL)
DATABASES = {
    'default': dj_database_url.config(
        default=os.environ.get('DATABASE_URL'),
        conn_max_age=600,
        conn_health_checks=True,
    )
}

# Ensure PostGIS engine
if DATABASES['default']:
    DATABASES['default']['ENGINE'] = 'django.contrib.gis.db.backends.postgis'

# CORS Configuration
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
]
CORS_ALLOWED_ORIGIN_REGEXES = []

# If PUBLIC_HOST given, add its exact origin
if PUBLIC_HOST:
    parsed = urlparse(PUBLIC_HOST)
    scheme = parsed.scheme or 'https'
    host = (parsed.netloc or PUBLIC_HOST.replace('https://', '').replace('http://', '')).strip('/')
    if host:
        origin = f"{scheme}://{host}"
        if origin not in CORS_ALLOWED_ORIGINS:
            CORS_ALLOWED_ORIGINS.append(origin)

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

# CSRF trusted origins (must be exact origins; compute from PUBLIC_HOST if provided)
CSRF_TRUSTED_ORIGINS = []
if PUBLIC_HOST:
    parsed = urlparse(PUBLIC_HOST)
    scheme = parsed.scheme or 'https'
    host = (parsed.netloc or PUBLIC_HOST.replace('https://', '').replace('http://', '')).strip('/')
    if host:
        CSRF_TRUSTED_ORIGINS.append(f"{scheme}://{host}")

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
}

# Static files configuration
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Additional static files directories
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'ankavidangeapp', 'static'),
]

# Whitenoise configuration for static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Africa/Abidjan'
USE_I18N = True
USE_TZ = True

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# GeoDjango configuration (Ubuntu environment)
GDAL_LIBRARY_PATH = os.environ.get('GDAL_LIBRARY_PATH')
GEOS_LIBRARY_PATH = os.environ.get('GEOS_LIBRARY_PATH')

# Security settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# Behind Nginx reverse proxy; trust X-Forwarded-Proto for SSL redirect and host header
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# Login URLs
LOGIN_URL = 'ankavidangeapp:login'
LOGIN_REDIRECT_URL = 'ankavidangeapp:landing'
LOGOUT_REDIRECT_URL = 'ankavidangeapp:logout'

# Session settings
SESSION_COOKIE_AGE = 3600
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
    },
}
