# ankavidange/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.generic import TemplateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django import forms
from django.urls import reverse_lazy
from django.utils import timezone
from django.db.models import Count, Sum, Q, Max, OuterRef, Subquery

from .models import PositionGPS, Vidangeur, Demande, Notification, User, VidangeurMecanique

class CustomUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label='Mot de passe', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirmer le mot de passe', widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ('phone_number', 'first_name', 'last_name')
        labels = {
            'phone_number': 'Numéro de téléphone',
            'first_name': 'Prénom',
            'last_name': 'Nom',
        }
    
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Les mots de passe ne correspondent pas.")
        return password2
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.role = User.Role.USAGER  # Default role for web registration
        if commit:
            user.save()
        return user

class LoginView(TemplateView):
    template_name = 'registrations/login.html'
    
    def post(self, request, *args, **kwargs):
        phone_number = request.POST.get('phone_number')
        password = request.POST.get('password')
        user = authenticate(request, username=phone_number, password=password)
        if user is not None:
            # Start session
            auth_login(request, user)

            # Role-based restriction: only USAGER and PROPRIETAIRE can access web login
            role = getattr(user, 'role', '')
            role_upper = role.upper() if isinstance(role, str) else ''
            allowed_roles = {'USAGER', 'PROPRIETAIRE'}
            if role_upper not in allowed_roles:
                logout(request)
                messages.error(request, "Accès refusé. Seuls les usagers et propriétaires peuvent se connecter ici.")
                return redirect('ankavidangeapp:auth:login')

            # Role-based redirect
            if role_upper == 'USAGER':
                return redirect('ankavidangeapp:landing')
            if role_upper == 'PROPRIETAIRE':
                return redirect('ankavidangeapp:proprietaire_dashboard')

            # Fallback: respect next= or go to landing
            next_url = request.GET.get('next')
            return redirect(next_url or 'ankavidangeapp:landing')
        else:
            messages.error(request, 'Identifiants invalides')
            return redirect('ankavidangeapp:auth:login')

class LogoutView(TemplateView):
    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect('ankavidangeapp:auth:login')

class RegisterView(CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('ankavidangeapp:auth:login')
    template_name = 'registrations/registration.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, 'Inscription réussie ! Vous pouvez maintenant vous connecter.')
        return response

class ProprietaireDashboardView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    """Vue pour le tableau de bord du propriétaire"""
    template_name = 'proprietaire/dashboard.html'
    login_url = 'ankavidangeapp:auth:login'
    
    def test_func(self):
        return self.request.user.is_authenticated and self.request.user.role == 'PROPRIETAIRE'
    
    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, 'Accès refusé. Vous devez être un propriétaire pour accéder à cette page.')
        return redirect('ankavidangeapp:landing')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # check user has a proprietaire profile
        proprietaire_profile = getattr(user, 'proprietaire_profile', None)
        if proprietaire_profile is None:
            messages.error(self.request, "Aucun profil propriétaire associé à cet utilisateur.")
            context.update({
                'total_camions': 0,
                'latest_positions': [],
                'recent_demandes': [],
                'unread_notifications': Notification.objects.filter(user=user, lue=False).order_by('-created_at')[:5],
            })
            return context
        
        # Statistiques de base
        context['total_camions'] = VidangeurMecanique.objects.filter(proprietaire__user=user, actif=True).count()
        
        # Dernières positions des vidangeurs
        latest_positions = PositionGPS.objects.filter(
            vidangeur__vidangeurmecanique__proprietaire__user=user
        ).select_related('vidangeur', 'vidangeur__vidangeurmecanique').order_by('vidangeur', '-timestamp').distinct('vidangeur')
        
        context['latest_positions'] = latest_positions
        
        # Dernières demandes
        context['recent_demandes'] = Demande.objects.filter(
            vidangeur__vidangeurmecanique__proprietaire__user=user
        ).select_related('vidangeur', 'vidangeur__vidangeurmecanique').order_by('-date_creation')[:5]
        
        # Notifications non lues
        context['unread_notifications'] = Notification.objects.filter(
            user=user,
            lue=False
        ).order_by('-created_at')[:5]
        
        return context

class LandingPageView(LoginRequiredMixin, TemplateView):
    """Vue pour le tableau de bord de l'application"""
    template_name = 'user/landing.html'
    login_url = 'ankavidangeapp:auth:login'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Ajoutez ici le contexte spécifique à la page d'accueil
        return context