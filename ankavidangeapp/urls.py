from django.urls import path, include
from django.views.generic import RedirectView

# Import des vues
from .views import (
    LogoutView, RegisterView, ProprietaireDashboardView, 
    LandingPageView, LoginView,
    search_vidangeurs, create_demande, list_user_demandes,
    ProprietaireDemandesListView, ProprietaireDemandeDetailView, ProprietaireDemandeEditView,
    ProprietaireVidangeursListView,
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
    path('proprietaire/vidangeurs/', ProprietaireVidangeursListView.as_view(), name='proprietaire_vidangeurs'),
    path('proprietaire/demandes/', ProprietaireDemandesListView.as_view(), name='proprietaire_demandes'),
    path('proprietaire/demandes/<int:pk>/', ProprietaireDemandeDetailView.as_view(), name='proprietaire_demande_detail'),
    path('proprietaire/demandes/<int:pk>/edit/', ProprietaireDemandeEditView.as_view(), name='proprietaire_demande_edit'),

    # Endpoints web (session-based) pour la recherche et création de demande
    path('web/vidangeurs/search/', search_vidangeurs, name='web_vidangeurs_search'),
    path('web/demandes/create/', create_demande, name='web_demande_create'),
    path('web/demandes/', list_user_demandes, name='web_demandes_list'),
    
    # URLs d'authentification - using a tuple with (patterns, app_name)
    path('auth/', include((auth_patterns, 'auth'), namespace='auth')),
]
