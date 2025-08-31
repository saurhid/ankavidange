from django.urls import path, include
from django.views.generic import RedirectView

# Import des vues
from .views import (
    LogoutView, RegisterView, ProprietaireDashboardView, 
    LandingPageView, LoginView
)

# Application namespace
app_name = 'ankavidangeapp'

# URLs d'authentification web
auth_patterns = [
    path('login/', LoginView.as_view(template_name='registrations/login.html'), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
]

# URLs de l'application
urlpatterns = [
    #redirect / to auth/login
    path('', RedirectView.as_view(url='auth/login/', permanent=False), name='login'),
    
    # Page d'accueil
    path('landing/', LandingPageView.as_view(), name='landing'),
    
    # Tableau de bord propriétaire
    path('proprietaire/', ProprietaireDashboardView.as_view(), name='proprietaire_dashboard'),
    
    # URLs d'authentification - using a tuple with (patterns, app_name)
    path('auth/', include((auth_patterns, 'auth'), namespace='auth')),
]
