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
from datetime import timedelta
from django.db.models import Count, Sum, Q, Max, OuterRef, Subquery, F
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.db.models import Min
from django.views import View
import json

from .models import PositionGPS, Vidangeur, Demande, Notification, User, VidangeurMecanique, VidangeurManuel

class ProprietaireRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    login_url = 'ankavidangeapp:auth:login'
    def test_func(self):
        return self.request.user.is_authenticated and self.request.user.role == User.Role.PROPRIETAIRE
    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, 'Accès refusé. Vous devez être un propriétaire pour accéder à cette page.')
        return redirect('ankavidangeapp:landing')

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

class ProprietaireDashboardView(ProprietaireRequiredMixin, TemplateView):
    """Vue pour le tableau de bord du propriétaire"""
    template_name = 'proprietaire/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # check user has a proprietaire profile
        proprietaire_profile = getattr(user, 'proprietaire_profile', None)
        if proprietaire_profile is None:
            messages.error(self.request, "Aucun profil propriétaire associé à cet utilisateur.")
            context.update({
                'total_vidangeur': 0,
                'camions_en_service': 0,
                'chauffeurs_hors_service': 0,
                'revenus_mois': 0,
                'dernieres_demandes': [],
                'unread_notifications': Notification.objects.filter(user=user, lue=False).order_by('-created_at')[:5],
            })
            return context
        
        # Base queryset: vidangeurs mécaniques du propriétaire
        vm_qs = VidangeurMecanique.objects.filter(proprietaire__user=user)

        # Statistiques de base attendues par le template
        context['total_vidangeur'] = vm_qs.count()
        context['camions_en_service'] = vm_qs.filter(statut__in=['DISPONIBLE', 'EN_MISSION']).count()
        context['chauffeurs_hors_service'] = vm_qs.filter(statut='INDISPONIBLE').count()

        # Revenus des 30 derniers jours (sommes budgets des demandes terminées)
        now = timezone.now()
        since = now - timedelta(days=30)
        revenus = (Demande.objects
                  .filter(
                      vidangeur__vidangeurmecanique__proprietaire__user=user,
                      statut='TERMINEE',
                      date_fin__gte=since,
                      date_fin__lte=now,
                  )
                  .aggregate(total=Sum('budget'))['total'] or 0)
        context['revenus_mois'] = float(revenus)

        # Dernières demandes (adapter aux champs utilisés par le template)
        dernieres = (Demande.objects
                     .filter(vidangeur__vidangeurmecanique__proprietaire__user=user)
                     .select_related('usager', 'vidangeur__user')
                     .order_by('-date_creation')[:5]
                     )
        # Annoter un alias 'montant' attendu par le template
        # Si l'annotation via queryset n'est pas possible ici (slice déjà appliquée), on complète en mémoire
        for d in dernieres:
            setattr(d, 'montant', d.budget)
        context['dernieres_demandes'] = dernieres

        # Vidangeurs mécaniques géolocalisés (pour affichage sur la carte)
        locs = (
            vm_qs.select_related('user')
                 .exclude(position_actuelle__isnull=True)
        )
        context['vidangeurs_geo'] = [
            {
                'id': v.id,
                'name': v.user.get_full_name(),
                'lat': v.latitude,
                'lng': v.longitude,
                'statut': v.statut,
                'capacite': v.capacite,
                'immatriculation': v.immatriculation,
            }
            for v in locs
        ]

        # Liste des vidangeurs mécaniques du propriétaire (proprietaire.id == vidangeur.proprietaire.id)
        vlist_qs = (
            VidangeurMecanique.objects
            .filter(proprietaire__user=user)
            .select_related('user', 'proprietaire')
            .order_by('user__last_name', 'user__first_name')
        )
        context['vidangeurs_mec'] = [
            {
                'id': v.id,
                'name': v.user.get_full_name() or v.user.phone_number,
                'immatriculation': v.immatriculation,
                'capacite': v.capacite,
                'statut': v.statut,
                'latitude': v.latitude,
                'longitude': v.longitude,
            }
            for v in vlist_qs
        ]

        # Notifications non lues
        context['unread_notifications'] = Notification.objects.filter(user=user, lue=False).order_by('-created_at')[:5]

        return context

class LandingPageView(LoginRequiredMixin, TemplateView):
    """Vue pour le tableau de bord de l'application"""
    template_name = 'user/landing.html'
    login_url = 'ankavidangeapp:auth:login'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Fournir les camions disponibles (statut DISPONIBLE) avec leur position actuelle
        #qs = (Vidangeur.objects
        #      .filter(actif=True, statut='DISPONIBLE')
        #      .select_related('user'))
        #available_trucks = []
        #for v in qs:
            # Utiliser la position actuelle si disponible
            #if v.position_actuelle:
                # Déterminer le type (mécanique / manuelle)
                #is_mec = VidangeurMecanique.objects.filter(pk=v.pk).exists()
                #available_trucks.append({
                 #     'id': v.id,
                 #     'name': v.user.get_full_name() or v.user.phone_number,
                 #     'phone': v.user.phone_number,
                 #     'type': 'MECANIQUE' if is_mec else 'MANUELLE',
                 #     'latitude': v.latitude,
                 #     'longitude': v.longitude,
                 #     'last_update': v.date_derniere_localisation.isoformat() if v.date_derniere_localisation else None,
                #})
        #context['available_trucks'] = available_trucks
        #return context

        vm_qs_mec = VidangeurMecanique.objects.filter(actif=True)
        vm_qs_man = VidangeurManuel.objects.filter(actif=True)

        locs_mec = (
            vm_qs_mec.select_related('user')
                 .exclude(position_actuelle__isnull=True)
        )
        locs_man = (
            vm_qs_man.select_related('user')
                 .exclude(position_actuelle__isnull=True)
        )

        context['vidangeurs_geo_user'] = [
            {
                'id': v.id,
                'name': v.user.get_full_name(),
                'lat': v.latitude,
                'lng': v.longitude,
                'statut': v.statut,
                'capacite': v.capacite,
                'immatriculation': v.immatriculation,
            }
            for v in (list(locs_mec) + list(locs_man))
        ]
        context['available_trucks'] = context['vidangeurs_geo_user']
        return context
# Session-based endpoints for web (no JWT required)

@login_required
@require_http_methods(["GET"])
def search_vidangeurs(request):
    """Return vidangeurs filtered by type and optional max budget using session auth."""
    type_vidange = request.GET.get('type_vidange')
    max_budget = request.GET.get('budget')
    results = []

    if type_vidange not in ['MECANIQUE', 'MANUELLE']:
        return JsonResponse({'detail': "Paramètre 'type_vidange' invalide"}, status=400)

    if type_vidange == 'MANUELLE':
        qs = VidangeurManuel.objects.filter(actif=True).select_related('user')
        if max_budget:
            try:
                max_b = float(max_budget)
                qs = qs.filter(tarif_manuel__lte=max_b)
            except ValueError:
                return JsonResponse({'detail': "Budget invalide"}, status=400)
        for v in qs:
            results.append({
                'id': v.id,
                'name': v.user.get_full_name(),
                'phone': v.user.phone_number,
                'type': 'MANUELLE',
                'price': float(v.tarif_manuel),
                'statut': getattr(v, 'statut', ''),
            })

    if type_vidange == 'MECANIQUE':
        qs = VidangeurMecanique.objects.filter(actif=True).select_related('user').annotate(
            min_price=Min('tarifs_centres__prix')
        )
        if max_budget:
            try:
                max_b = float(max_budget)
                qs = qs.filter(min_price__isnull=False, min_price__lte=max_b)
            except ValueError:
                return JsonResponse({'detail': "Budget invalide"}, status=400)
        for v in qs:
            if v.min_price is None:
                continue
            results.append({
                'id': v.id,
                'name': v.user.get_full_name(),
                'phone': v.user.phone_number,
                'type': 'MECANIQUE',
                'price': float(v.min_price),
                'statut': getattr(v, 'statut', ''),
                'capacity': v.capacite,
            })

    return JsonResponse({'count': len(results), 'results': results}, status=200)


@login_required
@require_POST
def create_demande(request):
    """Create a demande using session auth, expecting JSON payload from web."""
    user: User = request.user
    if user.role != User.Role.USAGER:
        return JsonResponse({'detail': "Seuls les usagers peuvent créer une demande."}, status=403)

    try:
        # Accept both JSON body and regular form POST
        if request.content_type and 'application/json' in request.content_type:
            data = json.loads(request.body.decode('utf-8') or '{}')
        else:
            data = {
                'adresse': request.POST.get('adresse'),
                'type_vidange': request.POST.get('type_vidange'),
                'volume_estime': request.POST.get('volume_estime'),
                'vidangeur_id': request.POST.get('vidangeur_id'),
                'budget': request.POST.get('budget'),
                'date_souhaitee': request.POST.get('date_souhaitee'),
                'commentaire': request.POST.get('commentaire'),
                'latitude': request.POST.get('latitude'),
                'longitude': request.POST.get('longitude'),
            }
    except Exception:
        data = {}

    required = ['adresse', 'type_vidange', 'volume_estime', 'vidangeur_id']
    if any(not data.get(k) for k in required):
        return JsonResponse({'detail': 'Champs requis manquants.'}, status=400)

    try:
        base = Vidangeur.objects.select_related('user').get(pk=data['vidangeur_id'])
    except Vidangeur.DoesNotExist:
        return JsonResponse({'detail': 'Vidangeur introuvable'}, status=400)

    mec = VidangeurMecanique.objects.filter(pk=base.pk).first()
    man = VidangeurManuel.objects.filter(pk=base.pk).first()
    vid = mec or man or base

    if data['type_vidange'] == 'MECANIQUE' and not mec:
        return JsonResponse({'detail': "Le vidangeur sélectionné n'est pas de type mécanique."}, status=400)
    if data['type_vidange'] == 'MANUELLE' and not man:
        return JsonResponse({'detail': "Le vidangeur sélectionné n'est pas de type manuelle."}, status=400)

    demande = Demande(
        usager=user,
        type_vidange=data['type_vidange'],
        adresse=data['adresse'],
        volume_estime=data['volume_estime'],
        budget=data.get('budget') or None,
        date_souhaitee=data.get('date_souhaitee') or timezone.now(),
        commentaire=data.get('commentaire', ''),
        vidangeur=vid,
        statut='EN_ATTENTE',
    )
    try:
        demande.full_clean(exclude=None)
        demande.save()
        # If coordinates provided, set position
        lat = data.get('latitude')
        lng = data.get('longitude')
        try:
            if lat is not None and lng is not None and str(lat) != '' and str(lng) != '':
                demande.set_position(float(lat), float(lng))
                demande.save(update_fields=['position'])
        except Exception:
            # ignore invalid coordinates; demande stays without position
            pass
    except Exception as e:
        return JsonResponse({'detail': str(e)}, status=400)

    return JsonResponse({
        'id': demande.id,
        'reference': demande.reference,
        'statut': demande.statut,
        'type_vidange': demande.type_vidange,
        'date_demande': demande.date_demande.isoformat(),
    }, status=201)


@login_required
@require_http_methods(["GET"])
def list_user_demandes(request):
    """List demandes for the logged-in user (session-based)."""
    qs = (Demande.objects
          .filter(usager=request.user)
          .order_by('-date_demande'))
    data = []
    for d in qs:
        data.append({
            'id': d.id,
            'reference': d.reference,
            'date_demande': d.date_demande.isoformat() if d.date_demande else None,
            'type_vidange': d.type_vidange,
            'budget': float(d.budget) if d.budget is not None else None,
            'statut': d.statut,
        })
    return JsonResponse(data, safe=False)

class ProprietaireDemandesListView(ProprietaireRequiredMixin, TemplateView):
    template_name = 'proprietaire/demandes_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        qs = (Demande.objects
              .filter(vidangeur__vidangeurmecanique__proprietaire__user=user)
              .select_related('usager', 'vidangeur__user')
              .order_by('-date_creation'))
        context['demandes'] = qs[:100]
        return context

class ProprietaireDemandeDetailView(ProprietaireRequiredMixin, TemplateView):
    template_name = 'proprietaire/demande_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        demande_id = self.kwargs.get('pk')
        demande = (Demande.objects
                   .select_related('usager', 'vidangeur__user')
                   .filter(id=demande_id, vidangeur__vidangeurmecanique__proprietaire__user=user)
                   .first())
        if not demande:
            messages.error(self.request, "Demande introuvable ou non autorisée.")
            return context
        context['demande'] = demande
        return context

class ProprietaireDemandeEditView(ProprietaireRequiredMixin, TemplateView):
    template_name = 'proprietaire/demande_edit.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        demande_id = self.kwargs.get('pk')
        demande = (Demande.objects
                   .select_related('usager', 'vidangeur__user')
                   .filter(id=demande_id, vidangeur__vidangeurmecanique__proprietaire__user=user)
                   .first())
        if not demande:
            messages.error(self.request, "Demande introuvable ou non autorisée.")
            return context
        context['demande'] = demande
        return context

class ProprietaireVidangeursListView(LoginRequiredMixin, TemplateView):
    template_name = 'proprietaire/vidangeurs_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Filtrer les vidangeurs mécaniques appartenant au propriétaire connecté
        vlist_qs = (
            VidangeurMecanique.objects
            .filter(proprietaire__user=user)
            .select_related('user', 'proprietaire')
            .order_by('user__last_name', 'user__first_name')
        )

        context['vidangeurs_mec'] = [
            {
                'id': v.id,
                'name': v.user.get_full_name() or v.user.username,
                'immatriculation': v.immatriculation,
                'capacite': v.capacite,
                'statut': v.statut,
                'latitude': v.latitude,
                'longitude': v.longitude,
            }
            for v in vlist_qs
        ]

        return context

class RootRedirectView(View):
    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            role = getattr(user, 'role', '')
            role_upper = role.upper() if isinstance(role, str) else ''
            if role_upper == 'PROPRIETAIRE':
                return redirect('ankavidangeapp:proprietaire_dashboard')
            # Default authenticated landing for other roles
            return redirect('ankavidangeapp:landing')
        # Not authenticated: go to login
        return redirect('ankavidangeapp:auth:login')