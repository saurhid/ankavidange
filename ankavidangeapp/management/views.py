from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.generic import TemplateView, ListView, DetailView, UpdateView
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.db.models import Count, Q, F, Value, CharField
from django.db.models.functions import Concat
from django.utils import timezone
from datetime import timedelta, datetime
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.contrib.auth import authenticate, login as auth_login, logout
from django.views.generic.edit import FormView, DeleteView
from django import forms
from django.contrib.gis.geos import Point
from ..models import Vidangeur, VidangeurMecanique, VidangeurManuel, PositionGPS, Demande, User, Proprietaire, CentreVidange, TarifCentreVidange

class LoginView(TemplateView):
    template_name = 'management/login.html'
    
    def post(self, request, *args, **kwargs):
        phone_number = request.POST.get('phone_number')
        password = request.POST.get('password')
        user = authenticate(request, username=phone_number, password=password)
        if user is not None:
            # Start session
            auth_login(request, user)

            # Redirect to management dashboard for staff/superusers
            if user.is_staff or user.is_superuser:
                return redirect('management:dashboard')

        else:
            messages.error(request, 'Identifiants invalides')
            return redirect('staff_login')

class LogoutView(TemplateView):
    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect('staff_login')

# Custom decorator for staff members
def staff_required(view_func):
    decorated_view = login_required(user_passes_test(
        lambda u: u.is_staff,
        login_url='staff_login',
        redirect_field_name=None
    )(view_func), login_url='staff_login')
    return decorated_view

class StaffRequiredMixin:
    @method_decorator(staff_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

class DashboardView(StaffRequiredMixin, TemplateView):
    template_name = 'management/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        today = timezone.now().date()
        
        # Get counts for dashboard cards
        stats = {
            'active_trucks': Vidangeur.objects.filter(actif=True).count(),
            'today_requests': Demande.objects.filter(date_creation__date=today).count(),
            'active_users': User.objects.filter(is_active=True).count(),
            'pending_requests': Demande.objects.filter(statut='EN_ATTENTE').count(),
        }
        
        # Get recent requests
        recent_requests = Demande.objects.select_related('usager', 'vidangeur', 'vidangeur__user').order_by('-date_creation')[:5]
        
        # Get weekly stats for chart
        week_ago = today - timedelta(days=6)
        weekly_stats = Demande.objects.filter(
            date_creation__date__gte=week_ago
        ).values('date_creation__date').annotate(
            total=Count('id')
        ).order_by('date_creation__date')
        
        # Format chart data
        chart_data = {
            'labels': [(today - timedelta(days=i)).strftime('%a') for i in range(6, -1, -1)],
            'data': [0] * 7
        }
        
        for stat in weekly_stats:
            day_index = (today - stat['date_creation__date'].date()).days
            if 0 <= day_index <= 6:
                chart_data['data'][6 - day_index] = stat['total']
        
        # Get active trucks with their latest position
        trucks = []
        for v in Vidangeur.objects.filter(actif=True).select_related('user'):
            latest_position = v.positions_gps.order_by('-timestamp').first()
            if latest_position:
                # Determine subtype
                vm = VidangeurMecanique.objects.filter(pk=v.pk).first()
                vman = None if vm else VidangeurManuel.objects.filter(pk=v.pk).first()
                trucks.append({
                    'id': v.id,
                    'type': 'Mécanique' if vm else 'Manuelle',
                    'immatriculation': getattr(vm, 'immatriculation', None),
                    'modele': getattr(vm, 'modele', None),
                    'statut': v.get_statut_display() if hasattr(v, 'get_statut_display') else v.statut,
                    'latitude': latest_position.latitude,
                    'longitude': latest_position.longitude,
                    'last_update': latest_position.timestamp,
                    'last_update_iso': latest_position.timestamp.isoformat() if latest_position.timestamp else None,
                    'last_update_ts': int(latest_position.timestamp.timestamp()) if latest_position.timestamp else None,
                    'chauffeur': v.user.get_full_name() if v.user else 'Aucun'
                })
        
        # Vidangeur status aggregation for pie chart
        active_vidangeurs = Vidangeur.objects.filter(actif=True)
        # En mission: has at least one ongoing Demande (EN_COURS)
        en_mission_ids = set(
            Demande.objects.filter(statut='EN_COURS', vidangeur__isnull=False)
            .values_list('vidangeur_id', flat=True)
        )
        indisponible_ids = set(
            active_vidangeurs.filter(statut='INDISPONIBLE').values_list('id', flat=True)
        )
        disponible_count = active_vidangeurs.exclude(id__in=en_mission_ids | indisponible_ids).count()
        en_mission_count = len(en_mission_ids & set(active_vidangeurs.values_list('id', flat=True)))
        indisponible_count = len(indisponible_ids)

        context.update({
            'title': 'Tableau de bord',
            'stats': stats,
            'recent_requests': recent_requests,
            'chart_data': chart_data,
            'trucks': trucks,
            'vid_status': {
                'labels': ['Disponible', 'En mission', 'Indisponible'],
                'data': [disponible_count, en_mission_count, indisponible_count],
                'colors': ['#198754', '#ffc107', '#dc3545'],
            },
        })
        return context

class TruckMapView(StaffRequiredMixin, TemplateView):
    template_name = 'management/truck_map.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        trucks = []
        for v in Vidangeur.objects.filter(actif=True).select_related('user'):
            latest_position = v.positions_gps.order_by('-timestamp').first()
            if latest_position:
                vm = VidangeurMecanique.objects.filter(pk=v.pk).first()
                vman = None if vm else VidangeurManuel.objects.filter(pk=v.pk).first()
                trucks.append({
                    'id': v.id,
                    'type': 'Mécanique' if vm else 'Manuelle',
                    'immatriculation': getattr(vm, 'immatriculation', None),
                    'modele': getattr(vm, 'modele', None),
                    'statut': v.get_statut_display() if hasattr(v, 'get_statut_display') else v.statut,
                    'latitude': latest_position.latitude,
                    'longitude': latest_position.longitude,
                    'last_update': latest_position.timestamp,
                    'last_update_iso': latest_position.timestamp.isoformat() if latest_position.timestamp else None,
                    'last_update_ts': int(latest_position.timestamp.timestamp()) if latest_position.timestamp else None,
                    'chauffeur': v.user.get_full_name() if v.user else 'Aucun'
                })
        
        # Centres actifs avec coordonnées (Point y=lat, x=lng)
        centres = []
        for c in CentreVidange.objects.filter(actif=True).exclude(position__isnull=True):
            lat = getattr(c.position, 'y', None)
            lng = getattr(c.position, 'x', None)
            if lat is None or lng is None:
                continue
            centres.append({
                'id': c.id,
                'name': c.nom,
                'latitude': lat,
                'longitude': lng,
            })
        
        context.update({
            'title': 'Suivi des camions en temps réel',
            'trucks': trucks,
            'centres': centres,
        })
        return context

class ReportsView(StaffRequiredMixin, TemplateView):
    template_name = 'management/reports.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add your report data here
        context['title'] = 'Rapports et statistiques'
        
        return context

class UserManagementView(StaffRequiredMixin, ListView):
    model = User
    template_name = 'management/user_list.html'
    context_object_name = 'users'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = super().get_queryset()
        search = self.request.GET.get('search', '')
        role = self.request.GET.get('role', '')
        is_active = self.request.GET.get('is_active', '')
        is_staff = self.request.GET.get('is_staff', '')
        
        if search:
            queryset = queryset.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search) |
                Q(phone_number__icontains=search)
            )
        if role:
            queryset = queryset.filter(role=role)
        if is_active in ['0', '1']:
            queryset = queryset.filter(is_active=(is_active == '1'))
        if is_staff in ['0', '1']:
            queryset = queryset.filter(is_staff=(is_staff == '1'))
        
        return queryset.order_by('-date_joined')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Gestion des utilisateurs'
        context['role_choices'] = User.Role.choices
        return context

class RequestFollowUpView(StaffRequiredMixin, ListView):
    model = Demande
    template_name = 'management/request_followup.html'
    context_object_name = 'requests'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = super().get_queryset().select_related('usager', 'vidangeur', 'vidangeur__user')
        status = self.request.GET.get('status', '')
        search = self.request.GET.get('search', '')
        
        if status:
            queryset = queryset.filter(statut=status)
        
        if search:
            queryset = queryset.filter(
                Q(id__icontains=search) |
                Q(adresse__icontains=search) |
                Q(usager__first_name__icontains=search) |
                Q(usager__last_name__icontains=search)
            )
        
        return queryset.order_by('-date_creation')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Suivi des demandes'
        context['status_choices'] = dict(Demande.STATUT_CHOICES)
        return context

class UserDetailView(StaffRequiredMixin, DetailView):
    model = User
    template_name = 'management/user_detail.html'
    context_object_name = 'user_obj'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Profil de {self.object.get_full_name()}'
        return context

class RequestDetailView(StaffRequiredMixin, DetailView):
    model = Demande
    template_name = 'management/request_detail.html'
    context_object_name = 'request_obj'
    
    def get_queryset(self):
        return super().get_queryset().select_related('usager', 'vidangeur', 'vidangeur__user')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f'Détails de la demande #{self.object.id}'
        return context

def update_request_status(request, pk, status):
    if not request.user.is_staff:
        return redirect('management:dashboard')
    
    demande = get_object_or_404(Demande, pk=pk)
    old_status = demande.get_statut_display()
    
    if status in dict(Demande.STATUT_CHOICES):
        demande.statut = status
        demande.save()
        messages.success(request, f'Le statut de la demande #{demande.id} a été mis à jour de "{old_status}" à "{demande.get_statut_display()}"')
    else:
        messages.error(request, 'Statut invalide')
    
    return redirect('management:request_detail', pk=pk)

class UserCreateForm(forms.ModelForm):
    password1 = forms.CharField(label='Mot de passe', widget=forms.PasswordInput, required=True)
    password2 = forms.CharField(label='Confirmer le mot de passe', widget=forms.PasswordInput, required=True)
    # Champs additionnels pour Proprietaire
    nom_societe = forms.CharField(label='Nom de la société', required=False)
    contact = forms.CharField(label='Contact', required=False)
    # Champs additionnels pour Vidangeur
    proprietaire = forms.ModelChoiceField(
        label='Propriétaire', required=False,
        queryset=Proprietaire.objects.select_related('user').order_by('user__last_name','user__first_name')
    )
    numero_permis = forms.CharField(label='Numéro de permis', required=False)
    immatriculation = forms.CharField(label='Immatriculation', required=False)
    marque = forms.CharField(label='Marque', required=False)
    modele = forms.CharField(label='Modèle', required=False)
    annee = forms.IntegerField(label='Année', required=False)
    capacite = forms.IntegerField(label='Capacité (L)', required=False)
    tarif_manuel = forms.DecimalField(label='Tarif (FCFA) — Vidangeur manuel', max_digits=10, decimal_places=2, min_value=0, required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'role', 'is_active', 'is_staff']

    def clean(self):
        cleaned = super().clean()
        pw1, pw2 = cleaned.get('password1'), cleaned.get('password2')
        if pw1 != pw2:
            raise forms.ValidationError('Les mots de passe ne correspondent pas.')
        role = cleaned.get('role')
        # Contraintes basiques selon rôle
        if role == User.Role.PROPRIETAIRE:
            if not cleaned.get('nom_societe') or not cleaned.get('contact'):
                raise forms.ValidationError("Nom de la société et Contact sont requis pour un Propriétaire.")
        if role == User.Role.VIDANGEUR_MEC:
            required_fields = ['numero_permis', 'immatriculation']
            for f in required_fields:
                if not cleaned.get(f):
                    raise forms.ValidationError(f"{f.replace('_',' ').title()} est requis pour un Vidangeur (Mécanique).")
        if role == User.Role.VIDANGEUR_MAN and cleaned.get('tarif_manuel') is None:
            raise forms.ValidationError('Tarif (manuel) est requis pour un Vidangeur (Manuelle).')
        return cleaned

    def save(self, commit=True):
        cleaned = self.cleaned_data
        password = cleaned.pop('password1')
        cleaned.pop('password2', None)
        # Extra fields
        extra_owner = {k: cleaned.pop(k, None) for k in ['nom_societe', 'contact']}
        extra_v_fields = {k: cleaned.pop(k, None) for k in ['proprietaire', 'numero_permis', 'immatriculation', 'marque', 'modele', 'annee', 'capacite', 'tarif_manuel']}
        # Create user via manager
        user = User.objects.create_user(phone_number=cleaned['phone_number'], password=password, **{k: cleaned[k] for k in ['first_name','last_name','email','role','is_active','is_staff']})
        # Create appropriate profile
        if user.role == User.Role.PROPRIETAIRE:
            Proprietaire.objects.create(user=user, nom_societe=extra_owner.get('nom_societe',''), contact=extra_owner.get('contact',''))
        elif user.role == User.Role.VIDANGEUR_MEC:
            VidangeurMecanique.objects.create(
                user=user,
                proprietaire=extra_v_fields.get('proprietaire'),
                numero_permis=extra_v_fields.get('numero_permis'),
                immatriculation=extra_v_fields.get('immatriculation'),
                marque=extra_v_fields.get('marque') or None,
                modele=extra_v_fields.get('modele') or None,
                annee=extra_v_fields.get('annee') or None,
                capacite=extra_v_fields.get('capacite') or None,
            )
        elif user.role == User.Role.VIDANGEUR_MAN:
            VidangeurManuel.objects.create(
                user=user,
                tarif_manuel=extra_v_fields.get('tarif_manuel')
            )
        return user

class UserUpdateForm(forms.ModelForm):
    # Optionally allow password reset; leave empty to keep
    new_password1 = forms.CharField(label='Nouveau mot de passe', widget=forms.PasswordInput, required=False)
    new_password2 = forms.CharField(label='Confirmer', widget=forms.PasswordInput, required=False)
    # Proprietaire extras
    nom_societe = forms.CharField(label='Nom de la société', required=False)
    contact = forms.CharField(label='Contact', required=False)
    # Vidangeur extras
    proprietaire = forms.ModelChoiceField(
        label='Propriétaire', required=False,
        queryset=Proprietaire.objects.select_related('user').order_by('user__last_name','user__first_name')
    )
    numero_permis = forms.CharField(label='Numéro de permis', required=False)
    immatriculation = forms.CharField(label='Immatriculation', required=False)
    marque = forms.CharField(label='Marque', required=False)
    modele = forms.CharField(label='Modèle', required=False)
    annee = forms.IntegerField(label='Année', required=False)
    capacite = forms.IntegerField(label='Capacité (L)', required=False)
    tarif_manuel = forms.DecimalField(label='Tarif (FCFA) — Vidangeur manuel', max_digits=10, decimal_places=2, min_value=0, required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'role', 'is_active', 'is_staff']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        user = self.instance
        # Prefill extra fields from profiles
        if hasattr(user, 'proprietaire_profile'):
            self.fields['nom_societe'].initial = user.proprietaire_profile.nom_societe
            self.fields['contact'].initial = user.proprietaire_profile.contact
        # Prefill from vidangeur subclasses
        vm = VidangeurMecanique.objects.filter(user=user).first()
        if vm:
            self.fields['numero_permis'].initial = vm.numero_permis
            self.fields['immatriculation'].initial = vm.immatriculation
            self.fields['marque'].initial = vm.marque
            self.fields['modele'].initial = vm.modele
            self.fields['annee'].initial = vm.annee
            self.fields['capacite'].initial = vm.capacite
            self.fields['proprietaire'].initial = vm.proprietaire_id
        else:
            vman = VidangeurManuel.objects.filter(user=user).first()
            if vman:
                self.fields['tarif_manuel'].initial = vman.tarif_manuel

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get('new_password1'), cleaned.get('new_password2')
        if p1 or p2:
            if p1 != p2:
                raise forms.ValidationError('Les mots de passe ne correspondent pas.')
        role = cleaned.get('role')
        if role == User.Role.PROPRIETAIRE:
            if not cleaned.get('nom_societe') or not cleaned.get('contact'):
                raise forms.ValidationError("Nom de la société et Contact sont requis pour un Propriétaire.")
        if role == User.Role.VIDANGEUR_MEC:
            required_fields = ['numero_permis', 'immatriculation']
            for f in required_fields:
                if not cleaned.get(f):
                    raise forms.ValidationError(f"{f.replace('_',' ').title()} est requis pour un Vidangeur (Mécanique).")
        elif role == User.Role.VIDANGEUR_MAN:
            if cleaned.get('tarif_manuel') is None:
                raise forms.ValidationError('Tarif (manuel) est requis pour un Vidangeur (Manuelle).')
        return cleaned

    def save(self, commit=True):
        user = super().save(commit)
        cleaned = self.cleaned_data
        # Password change
        if cleaned.get('new_password1'):
            user.set_password(cleaned['new_password1'])
            user.save(update_fields=['password'])
        # Ensure / update profiles
        if user.role == User.Role.PROPRIETAIRE:
            prop, created = Proprietaire.objects.get_or_create(user=user, defaults={
                'nom_societe': cleaned.get('nom_societe',''),
                'contact': cleaned.get('contact','')
            })
            if not created:
                prop.nom_societe = cleaned.get('nom_societe','')
                prop.contact = cleaned.get('contact','')
                prop.save()
            # Clean up any vidangeur subclasses if role changed away from vidangeur
            VidangeurMecanique.objects.filter(user=user).delete()
            VidangeurManuel.objects.filter(user=user).delete()
        elif user.role == User.Role.VIDANGEUR_MEC:
            # Remove manual subclass if exists
            VidangeurManuel.objects.filter(user=user).delete()
            vm, created = VidangeurMecanique.objects.get_or_create(user=user, defaults={
                'proprietaire': cleaned.get('proprietaire'),
                'numero_permis': cleaned.get('numero_permis'),
                'immatriculation': cleaned.get('immatriculation'),
                'marque': cleaned.get('marque') or None,
                'modele': cleaned.get('modele') or None,
                'annee': cleaned.get('annee') or None,
                'capacite': cleaned.get('capacite') or None,
            })
            if not created:
                vm.proprietaire = cleaned.get('proprietaire')
                vm.numero_permis = cleaned.get('numero_permis')
                vm.immatriculation = cleaned.get('immatriculation')
                vm.marque = cleaned.get('marque') or None
                vm.modele = cleaned.get('modele') or None
                vm.annee = cleaned.get('annee') or None
                vm.capacite = cleaned.get('capacite') or None
                vm.full_clean()
                vm.save()
        elif user.role == User.Role.VIDANGEUR_MAN:
            # Remove mechanical subclass if exists
            VidangeurMecanique.objects.filter(user=user).delete()
            vman, created = VidangeurManuel.objects.get_or_create(user=user, defaults={
                'tarif_manuel': cleaned.get('tarif_manuel')
            })
            if not created:
                vman.tarif_manuel = cleaned.get('tarif_manuel')
                vman.full_clean()
                vman.save(update_fields=['tarif_manuel'])
        return user

class UserCreateView(StaffRequiredMixin, FormView):
    template_name = 'management/user_form.html'
    form_class = UserCreateForm
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form):
        form.save()
        messages.success(self.request, "Utilisateur créé avec succès")
        return super().form_valid(form)

class UserUpdateView(StaffRequiredMixin, UpdateView):
    model = User
    template_name = 'management/user_form.html'
    form_class = UserUpdateForm
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form):
        messages.success(self.request, "Utilisateur mis à jour avec succès")
        return super().form_valid(form)

class UserDeleteView(StaffRequiredMixin, DeleteView):
    model = User
    template_name = 'management/user_confirm_delete.html'
    success_url = reverse_lazy('management:user_management')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, "Utilisateur supprimé avec succès")
        return super().delete(request, *args, **kwargs)

class VidangeurTarifsView(StaffRequiredMixin, TemplateView):
    template_name = 'management/vidangeur_tarifs.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vidangeur_id = self.kwargs.get('pk')
        v = get_object_or_404(Vidangeur.objects.select_related('user'), pk=vidangeur_id)
        # Determine subclass
        vm = VidangeurMecanique.objects.filter(pk=vidangeur_id).select_related('user').first()
        is_mec = vm is not None
        context['vidangeur'] = v
        context['is_mec'] = is_mec
        context['title'] = f"Tarifs - {v.user.get_full_name()} ({'Mécanique' if is_mec else 'Manuelle'})"
        if is_mec:
            centres = CentreVidange.objects.order_by('nom')
            tarifs = {t.centre_id: t for t in TarifCentreVidange.objects.filter(vidangeur=vm)}
            context['rows'] = [{'centre': c, 'tarif': tarifs.get(c.id)} for c in centres]
        else:
            vman = VidangeurManuel.objects.filter(pk=vidangeur_id).first()
            context['tarif_manuel'] = vman.tarif_manuel if vman else None
        return context

    def post(self, request, *args, **kwargs):
        vidangeur_pk = kwargs.get('pk')
        vm = VidangeurMecanique.objects.filter(pk=vidangeur_pk).first()
        if vm:
            centres = CentreVidange.objects.all()
            updated = 0
            for c in centres:
                key = f'prix_{c.id}'
                raw = request.POST.get(key)
                if raw is None:
                    continue
                raw = raw.strip()
                if raw == '':
                    # If empty, deactivate any existing tarif
                    TarifCentreVidange.objects.filter(vidangeur=vm, centre=c).update(actif=False)
                    continue
                try:
                    prix = float(raw)
                except ValueError:
                    messages.error(request, f"Prix invalide pour le centre '{c.nom}'.")
                    return redirect('management:vidangeur_tarifs', pk=vidangeur_pk)
                TarifCentreVidange.objects.update_or_create(
                    vidangeur=vm, centre=c, defaults={'prix': prix, 'actif': True}
                )
                updated += 1
            messages.success(request, f"Tarifs mis à jour ({updated} centre(s)).")
        else:
            vman = get_object_or_404(VidangeurManuel, pk=vidangeur_pk)
            raw = request.POST.get('tarif_manuel', '').strip()
            if raw == '':
                vman.tarif_manuel = None
            else:
                try:
                    vman.tarif_manuel = float(raw)
                except ValueError:
                    messages.error(request, "Tarif invalide.")
                    return redirect('management:vidangeur_tarifs', pk=vidangeur_pk)
            try:
                vman.full_clean()
            except forms.ValidationError as e:
                messages.error(request, '; '.join([f"{k}: {','.join(v)}" for k, v in e.message_dict.items()]))
                return redirect('management:vidangeur_tarifs', pk=vidangeur_pk)
            vman.save(update_fields=['tarif_manuel'])
            messages.success(request, "Tarif mis à jour.")
        return redirect('management:vidangeur_tarifs', pk=vidangeur_pk)

class TarifsListView(StaffRequiredMixin, ListView):
    template_name = 'management/tarifs_list.html'
    context_object_name = 'tarifs'
    paginate_by = 25

    def get_queryset(self):
        qs = TarifCentreVidange.objects.select_related('vidangeur', 'vidangeur__user', 'centre')
        # only MEC vidangeurs
        # (no filter needed; FK already targets VidangeurMecanique)
        # qs = qs.filter(vidangeur__type=Vidangeur.Type.MEC)
        # Filters
        search = self.request.GET.get('search', '').strip()
        centre_id = self.request.GET.get('centre')
        actif = self.request.GET.get('actif')
        if search:
            qs = qs.filter(
                Q(vidangeur__user__first_name__icontains=search) |
                Q(vidangeur__user__last_name__icontains=search) |
                Q(vidangeur__immatriculation__icontains=search) |
                Q(centre__nom__icontains=search)
            )
        if centre_id:
            qs = qs.filter(centre_id=centre_id)
        if actif in ['0', '1']:
            qs = qs.filter(actif=(actif == '1'))
        return qs.order_by('centre__nom', 'vidangeur__user__last_name', 'vidangeur__user__first_name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Tarifs (Mécaniques)'
        context['centres'] = CentreVidange.objects.order_by('nom')
        return context

class TarifCreateForm(forms.Form):
    vidangeur = forms.ModelChoiceField(
        label='Vidangeur (Mécanique)',
        queryset=VidangeurMecanique.objects.select_related('user').order_by('user__last_name','user__first_name')
    )
    centre = forms.ModelChoiceField(label='Centre', queryset=CentreVidange.objects.order_by('nom'))
    prix = forms.DecimalField(label='Tarif (FCFA)', max_digits=10, decimal_places=2, min_value=0)
    actif = forms.BooleanField(label='Actif', required=False, initial=True)

    def clean(self):
        cleaned = super().clean()
        return cleaned

class TarifsCreateView(StaffRequiredMixin, FormView):
    template_name = 'management/tarif_form.html'
    form_class = TarifCreateForm
    success_url = reverse_lazy('management:tarifs_list')

    def form_valid(self, form):
        v = form.cleaned_data['vidangeur']
        c = form.cleaned_data['centre']
        prix = form.cleaned_data['prix']
        actif = form.cleaned_data['actif']
        obj, created = TarifCentreVidange.objects.update_or_create(
            vidangeur=v, centre=c, defaults={'prix': prix, 'actif': actif}
        )
        if created:
            messages.success(self.request, 'Tarif créé avec succès.')
        else:
            messages.success(self.request, 'Tarif mis à jour avec succès.')
        return super().form_valid(form)

class CentreListView(StaffRequiredMixin, TemplateView):
    template_name = 'management/centres_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        centres = CentreVidange.objects.order_by('-date_creation')
        context['centres'] = centres
        context['title'] = 'Centres de vidange'
        return context

    def post(self, request, *args, **kwargs):
        centre_id = (request.POST.get('centre_id') or '').strip()
        nom = (request.POST.get('nom') or '').strip()
        lat = (request.POST.get('latitude') or '').strip()
        lng = (request.POST.get('longitude') or '').strip()
        actif = True if request.POST.get('actif') == 'on' else False

        if not nom:
            messages.error(request, "Le nom du centre est requis.")
            return redirect('management:centres_list')

        if centre_id:
            # Update existing
            centre = get_object_or_404(CentreVidange, pk=centre_id)
            centre.nom = nom
            centre.actif = actif
            if lat and lng:
                try:
                    centre.position = Point(float(lng), float(lat))
                except ValueError:
                    messages.error(request, "Coordonnées invalides. Les autres modifications ont été prises en compte.")
            centre.save()
            messages.success(request, "Centre mis à jour avec succès.")
        else:
            # Create new
            centre = CentreVidange(nom=nom, actif=actif)
            if lat and lng:
                try:
                    centre.position = Point(float(lng), float(lat))
                except ValueError:
                    messages.error(request, "Coordonnées invalides. Le centre a été créé sans position.")
            centre.save()
            messages.success(request, "Centre créé avec succès.")
        return redirect('management:centres_list')
