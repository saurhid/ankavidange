from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Skip for non-API routes
        if not request.path.startswith('/api/'):
            return

        # Skip for login/register endpoints
        if request.path in ['/api/auth/login/', '/api/auth/register/', '/api/auth/token/refresh/']:
            return

        # Get token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '').split()
        
        if len(auth_header) == 2 and auth_header[0].lower() == 'bearer':
            try:
                auth = JWTAuthentication()
                validated_token = auth.get_validated_token(auth_header[1])
                request.user = auth.get_user(validated_token)
            except Exception as e:
                return JsonResponse(
                    {'error': 'Invalid token', 'detail': str(e)},
                    status=401
                )
        else:
            # For API routes, require authentication
            if request.path.startswith('/api/'):
                return JsonResponse(
                    {'error': 'Authentication credentials were not provided.'},
                    status=401
                )
