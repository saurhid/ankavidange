"""
API module for Anka Vidange application.

This module contains all the API views, serializers, and URL configurations
for the Anka Vidange application.
"""

# Import views
from .views import (
    APiRegisterView,
    CustomTokenObtainPairView,
    TokenRefreshView,
    UserViewSet,
)

# Import serializers
from .serializers import (
    CustomTokenObtainPairSerializer,
    TokenRefreshSerializer,
    UserSerializer,
    UserCreateSerializer,
)

# Import URLs
from . import urls as api_urls

__all__ = [
    # Views
    'APiRegisterView',
    'CustomTokenObtainPairView',
    'TokenRefreshView',
    'UserViewSet',
    
    # Serializers
    'CustomTokenObtainPairSerializer',
    'TokenRefreshSerializer',
    'UserSerializer',
    'UserCreateSerializer',
    
    # URLs
    'api_urls',
]
