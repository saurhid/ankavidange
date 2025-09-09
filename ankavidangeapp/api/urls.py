from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
app_name = 'api'


router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')

urlpatterns = [
    path('auth/register/', views.APiRegisterView.as_view(), name='register'),
    path('auth/login/', views.CustomTokenObtainPairView.as_view(), name='login'),
    path('auth/token/refresh/', views.TokenRefreshView.as_view(), name='token_refresh'),
    # Authenticated API endpoints
    # Position endpoints
    path('centres-positions/', views.CentresPositionsAPIView.as_view(), name='centres_positions'),
    path('vidangeurs-positions/', views.VidangeursPositionsAPIView.as_view(), name='vidangeurs_positions'),
    # Vidangeur endpoints
    path('vidangeur/status/', views.VidangeurStatusView.as_view(), name='vidangeur_status'),
    path('vidangeur/profile/', views.VidangeurProfileView.as_view(), name='vidangeur_profile'),
    path('vidangeur/position/', views.PositionCreateAPIView.as_view(), name='vidangeur_position'),
    # FCM endpoints
    path('fcm/register/', views.FCMRegisterView.as_view(), name='fcm_register'),
    path('fcm/unregister/', views.FCMUnregisterView.as_view(), name='fcm_unregister'),
    path('notifications/test/', views.FCMTestView.as_view(), name='notifications_test'),
    # Demands endpoints
    path('demands/accepted/', views.AcceptedDemandsView.as_view(), name='accepted_demands'),
    path('demands/<int:pk>/accept/', views.AcceptDemandView.as_view(), name='demand_accept'),
    path('demands/<int:pk>/complete/', views.CompleteDemandView.as_view(), name='demand_complete'),
    path('demands/<int:pk>/cancel/', views.CancelDemandView.as_view(), name='demand_cancel'),
    # New endpoints for mobile demande flow
    path('vidangeurs/search/', views.SearchVidangeursView.as_view(), name='vidangeurs_search'),
    path('demands/create/', views.DemandeCreateView.as_view(), name='demand_create'),
    # Owner endpoints
    path('owner/profile/', views.OwnerProfileView.as_view(), name='owner_profile'),
    path('owner/dashboard/', views.OwnerDashboardView.as_view(), name='owner_dashboard'),
    path('owner/trucks/', views.OwnerTrucksView.as_view(), name='owner_trucks'),
    path('owner/demandes/', views.OwnerDemandesView.as_view(), name='owner_demandes'),
    path('owner/revenue/', views.OwnerRevenueView.as_view(), name='owner_revenue'),
    path('owner/vidangeurs/stats/', views.OwnerVidangeurDemandesStatsView.as_view(), name='owner_vidangeur_stats'),
    path('', include(router.urls)),
]
