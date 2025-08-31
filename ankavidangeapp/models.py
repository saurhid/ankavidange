from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models, IntegrityError
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.gis.db import models as gis_models
from django.contrib.gis.geos import Point
from django.utils import timezone
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError(_('Le numéro de téléphone est obligatoire'))
        role = extra_fields.get('role')
        if not role:
            raise ValueError(_('Le rôle est obligatoire'))
        if role not in dict(User.Role.choices):
            raise ValueError(_('Rôle invalide'))
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', User.Role.ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(phone_number, password, **extra_fields)

class User(AbstractUser, PermissionsMixin):
    class Role(models.TextChoices):
        USAGER = 'USAGER', _('Usager')
        VIDANGEUR_MEC = 'VIDANGEUR_MEC', _('Vidangeur (Mécanique)')
        VIDANGEUR_MAN = 'VIDANGEUR_MAN', _('Vidangeur (Manuelle)')
        PROPRIETAIRE = 'PROPRIETAIRE', _('Propriétaire')
        ADMIN = 'ADMIN', _('Administrateur')

    phone_number = models.CharField(_('téléphone'), max_length=20, unique=True)
    role = models.CharField(_('rôle'), max_length=20, choices=Role.choices)
    username = None
    is_active = models.BooleanField(_('actif'), default=True)
    is_staff = models.BooleanField(_('membre du staff'), default=False)
    is_available = models.BooleanField(_('disponible'), default=True)
    fcm_token = models.CharField(_('token FCM'), max_length=255, blank=True, null=True)
    date_joined = models.DateTimeField(_('date d\'inscription'), default=timezone.now)
    last_login = models.DateTimeField(_('dernière connexion'), null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'email', 'role']

    class Meta:
        verbose_name = _('utilisateur')
        verbose_name_plural = _('utilisateurs')
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['role']),
            models.Index(fields=['is_available']),
        ]

    def __str__(self):
        return f"{self.get_full_name()} ({self.phone_number})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def usager(self):
        return self.usager_profile if hasattr(self, 'usager_profile') else None

    @property
    def proprietaire(self):
        return self.proprietaire_profile if hasattr(self, 'proprietaire_profile') else None

class Profil(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='%(class)s_profile',
        verbose_name=_('utilisateur')
    )
    adresse = models.TextField(_('adresse complète'), blank=True)
    created_at = models.DateTimeField(_('créé le'), auto_now_add=True)
    updated_at = models.DateTimeField(_('mis à jour le'), auto_now=True)

    class Meta:
        abstract = True

    def __str__(self):
        return f"Profil de {self.user.get_full_name()}"

class Proprietaire(Profil):
    nom_societe = models.CharField(_('nom de la société'), max_length=100)
    contact = models.CharField(_('contact'), max_length=100)
    verification_status = models.CharField(
        _('statut de vérification'),
        max_length=20,
        choices=[
            ('EN_ATTENTE', 'En attente'),
            ('VERIFIE', 'Vérifié'),
            ('REJETE', 'Rejeté')
        ],
        default='EN_ATTENTE'
    )
    date_verification = models.DateTimeField(_('date de vérification'), null=True, blank=True)
    notes_verification = models.TextField(_('notes de vérification'), blank=True)

    class Meta:
        verbose_name = _('propriétaire')
        verbose_name_plural = _('propriétaires')

    def save(self, *args, **kwargs):
        if not self.user.role == User.Role.PROPRIETAIRE:
            raise ValueError("Le rôle de l'utilisateur doit être 'PROPRIETAIRE'")
        super().save(*args, **kwargs)

class CentreVidange(models.Model):
    nom = models.CharField(_('nom du centre'), max_length=255)
    position = gis_models.PointField(_('position géographique'), srid=4326, null=True, blank=True)
    actif = models.BooleanField(_('actif'), default=False)
    date_creation = models.DateTimeField(_('date de création'), default=timezone.now)

    class Meta:
        verbose_name = _('centre de vidange')
        verbose_name_plural = _('centres de vidange')
        ordering = ['nom']

    def __str__(self):
        return self.nom

    @property
    def latitude(self):
        return self.position.y if self.position else None

    @property
    def longitude(self):
        return self.position.x if self.position else None

    def set_position(self, latitude, longitude):
        self.position = Point(longitude, latitude)

class Vidangeur(models.Model):
    STATUT_CHOICES = [
        ('DISPONIBLE', 'Disponible'),
        ('EN_MISSION', 'En mission'),
        ('INDISPONIBLE', 'Indisponible'),
    ]

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='vidangeur',
        verbose_name=_('utilisateur'),
        limit_choices_to={'role__in': [User.Role.VIDANGEUR_MEC, User.Role.VIDANGEUR_MAN]}
    )
    note_moyenne = models.FloatField(_('note moyenne'), default=0.0, validators=[MinValueValidator(0), MaxValueValidator(5)])
    nombre_notes = models.PositiveIntegerField(_('nombre de notes'), default=0)
    statut = models.CharField(_('statut'), max_length=20, choices=STATUT_CHOICES, default='DISPONIBLE')
    position_actuelle = gis_models.PointField(_('position actuelle'), srid=4326, null=True, blank=True)
    date_derniere_localisation = models.DateTimeField(_('dernière localisation'), null=True, blank=True)
    actif = models.BooleanField(_('actif'), default=True)
    date_creation = models.DateTimeField(_('date de création'), default=timezone.now)
    date_maj = models.DateTimeField(_('date de mise à jour'), auto_now=True)

    class Meta:
        verbose_name = _('vidangeur')
        verbose_name_plural = _('vidangeurs')
        ordering = ['-date_creation']
        indexes = [
            models.Index(fields=['statut']),
        ]

    def __str__(self):
        return f"{self.user.get_full_name()}"

    @property
    def latitude(self):
        return self.position_actuelle.y if self.position_actuelle else None

    @property
    def longitude(self):
        return self.position_actuelle.x if self.position_actuelle else None

    def mettre_a_jour_position(self, latitude, longitude):
        self.position_actuelle = Point(longitude, latitude)
        self.date_derniere_localisation = timezone.now()
        self.save(update_fields=['position_actuelle', 'date_derniere_localisation'])

class VidangeurMecanique(Vidangeur):
    proprietaire = models.ForeignKey(
        Proprietaire,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='vidangeurs',
        verbose_name=_('propriétaire')
    )
    numero_permis = models.CharField(_('numéro de permis'), max_length=50, unique=True)
    immatriculation = models.CharField(_('immatriculation'), max_length=20, unique=True)
    marque = models.CharField(_('marque'), max_length=100, null=True, blank=True)
    modele = models.CharField(_('modèle'), max_length=100, null=True, blank=True)
    annee = models.PositiveIntegerField(_('année de fabrication'), null=True, blank=True)
    capacite = models.PositiveIntegerField(_('capacité (en litres)'), null=True, blank=True)
    centres = models.ManyToManyField(
        'CentreVidange',
        through='TarifCentreVidange',
        related_name='vidangeurs_m2m',
        verbose_name=_('centres de vidange'),
        blank=True,
    )

    class Meta:
        verbose_name = _('vidangeur mécanique')
        verbose_name_plural = _('vidangeurs mécaniques')

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.immatriculation} (Mécanique)"

    def clean(self):
        super().clean()
        if self.user and self.user.role != User.Role.VIDANGEUR_MEC:
            raise ValidationError({'user': _("L'utilisateur doit avoir le rôle Vidangeur (Mécanique)")})

    def set_tarif_pour_centre(self, centre: 'CentreVidange', prix):
        obj, _created = TarifCentreVidange.objects.update_or_create(
            vidangeur=self, centre=centre, defaults={'prix': prix, 'actif': True}
        )
        return obj

    def get_tarif_pour_centre(self, centre: 'CentreVidange'):
        return TarifCentreVidange.objects.filter(vidangeur=self, centre=centre, actif=True).first()

class VidangeurManuel(Vidangeur):
    tarif_manuel = models.DecimalField(_('tarif (manuel)'), max_digits=10, decimal_places=2)

    class Meta:
        verbose_name = _('vidangeur manuel')
        verbose_name_plural = _('vidangeurs manuels')

    def __str__(self):
        return f"{self.user.get_full_name()} (Manuel)"

    def clean(self):
        super().clean()
        if self.user and self.user.role != User.Role.VIDANGEUR_MAN:
            raise ValidationError({'user': _("L'utilisateur doit avoir le rôle Vidangeur (Manuelle)")})

class TarifCentreVidange(models.Model):
    """Relation Vidangeur <-> CentreVidange avec tarif spécifique."""
    vidangeur = models.ForeignKey(
        VidangeurMecanique,
        on_delete=models.CASCADE,
        related_name='tarifs_centres'
    )
    centre = models.ForeignKey(
        CentreVidange,
        on_delete=models.CASCADE,
        related_name='tarifs_vidangeurs'
    )
    prix = models.DecimalField(_('prix'), max_digits=10, decimal_places=2)
    actif = models.BooleanField(_('actif'), default=True)
    created_at = models.DateTimeField(_('créé le'), auto_now_add=True)
    updated_at = models.DateTimeField(_('mis à jour le'), auto_now=True)

    class Meta:
        verbose_name = _('tarif centre-vidangeur')
        verbose_name_plural = _('tarifs centre-vidangeur')
        unique_together = ('vidangeur', 'centre')
        indexes = [
            models.Index(fields=['vidangeur', 'centre']),
            models.Index(fields=['actif']),
        ]

    def __str__(self):
        return f"{self.vidangeur} @ {self.centre} -> {self.prix}"

class Demande(models.Model):
    STATUT_CHOICES = [
        ('EN_ATTENTE', 'En attente'),
        ('VALIDE', 'Validée'),
        ('EN_COURS', 'En cours'),
        ('TERMINEE', 'Terminée'),
        ('ANNULEE', 'Annulée'),
    ]

    TYPE_VIDANGE_CHOICES = [
        ('MECANIQUE', 'Mécanique'),
        ('MANUELLE', 'Manuelle'),

    ]

    TYPE_FOSSE_CHOICES = [
        ('SIMPLE', 'Simple'),
        ('GRANDE', 'Grande'),

    ]

    usager = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='demandes_vidange',
        verbose_name=_('usager'),
        limit_choices_to={'role': User.Role.USAGER}
    )
    type_vidange = models.CharField(_('type de vidange'), max_length=20, choices=TYPE_VIDANGE_CHOICES, default='MECANIQUE')
    date_demande = models.DateTimeField(_('date de la demande'), default=timezone.now)
    date_souhaitee = models.DateTimeField(_('date souhaitée'), default=timezone.now)
    statut = models.CharField(_('statut'), max_length=20, choices=STATUT_CHOICES, default='EN_ATTENTE')
    adresse = models.TextField(_('adresse de vidange'))
    volume_estime = models.CharField(_('volume'), max_length=20, choices=TYPE_FOSSE_CHOICES, default='SIMPLE')
    budget = models.DecimalField(_('budget'), max_digits=10, decimal_places=2, null=True, blank=True)
    vidangeur = models.ForeignKey(
        Vidangeur,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='demandes',
        verbose_name=_('vidangeur affecté')
    )
    note = models.PositiveSmallIntegerField(
        _('note'),
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    commentaire = models.TextField(_('commentaire'), blank=True)
    date_creation = models.DateTimeField(_('date de création'), default=timezone.now)
    date_maj = models.DateTimeField(_('date de mise à jour'), auto_now=True)
    reference = models.CharField(_('référence'), max_length=32, unique=True, blank=True)
    position = gis_models.PointField(_('position géographique'), srid=4326, null=True, blank=True)
    date_debut_intervention = models.DateTimeField(_('début intervention'), null=True, blank=True)
    date_fin_intervention = models.DateTimeField(_('fin intervention'), null=True, blank=True)
    date_debut = models.DateTimeField(_('date début'), null=True, blank=True)
    date_fin = models.DateTimeField(_('date fin'), null=True, blank=True)
    volume_traite = models.PositiveIntegerField(_('volume traité (L)'), null=True, blank=True)

    class Meta:
        verbose_name = _('demande de vidange')
        verbose_name_plural = _('demandes de vidange')
        ordering = ['-date_demande']
        indexes = [
            models.Index(fields=['statut']),
            models.Index(fields=['type_vidange']),
            models.Index(fields=['date_demande']),
            models.Index(fields=['usager']),
            models.Index(fields=['vidangeur']),
        ]

    def __str__(self):
        return f"Demande {self.reference} - {self.usager.get_full_name()}"

    def save(self, *args, **kwargs):
        attempts = 0
        while True:
            if not self.reference:
                # Génération d'une référence unique (ex: DV-20230816-XXXX)
                date_prefix = timezone.now().strftime('%Y%m%d')
                last_demande = Demande.objects.filter(
                    reference__startswith=f"DV-{date_prefix}-"
                ).order_by('-reference').first()
                if last_demande:
                    last_num = int(last_demande.reference.split('-')[-1])
                    new_num = last_num + 1
                else:
                    new_num = 1
                self.reference = f"DV-{date_prefix}-{new_num:04d}"
            try:
                super().save(*args, **kwargs)
                break
            except IntegrityError as e:
                # Probable collision sur reference; on réessaie quelques fois
                if 'reference' in str(e).lower() and attempts < 3:
                    attempts += 1
                    self.reference = None
                    continue
                raise

    @property
    def latitude(self):
        return self.position.y if self.position else None

    @property
    def longitude(self):
        return self.position.x if self.position else None

    def set_position(self, latitude, longitude):
        self.position = Point(longitude, latitude)

    def demarrer_intervention(self):
        if self.statut not in ['VALIDE', 'EN_ATTENTE']:
            raise ValueError("Impossible de démarrer l'intervention avec le statut actuel")
        
        self.statut = 'EN_COURS'
        self.date_debut_intervention = timezone.now()
        self.save(update_fields=['statut', 'date_debut_intervention'])

    def terminer_intervention(self):
        if self.statut != 'EN_COURS':
            raise ValueError("Aucune intervention en cours à terminer")
        
        self.statut = 'TERMINEE'
        self.date_fin_intervention = timezone.now()
        self.save(update_fields=['statut', 'date_fin_intervention'])
    def accepter_par(self, vidangeur: 'Vidangeur'):
        if self.statut != 'EN_ATTENTE':
            raise ValidationError("Seules les demandes en attente peuvent être acceptées")
        
        if not isinstance(vidangeur, Vidangeur):
            raise ValidationError("Objet vidangeur invalide")
        # Cohérence type demande <-> classe du vidangeur
        from .models import VidangeurMecanique, VidangeurManuel
        if (self.type_vidange == 'MECANIQUE' and not isinstance(vidangeur, VidangeurMecanique)) or \
           (self.type_vidange == 'MANUELLE' and not isinstance(vidangeur, VidangeurManuel)):
            raise ValidationError("Le type du vidangeur ne correspond pas au type de vidange")
        self.vidangeur = vidangeur
        self.statut = 'EN_COURS'
        self.date_debut = timezone.now()
        self.save()

    def terminer(self, volume_traite=None):
        if self.statut != 'EN_COURS':
            raise ValidationError("Seules les demandes en cours peuvent être terminées")
        
        self.statut = 'TERMINEE'
        self.date_fin = timezone.now()
        if volume_traite:
            self.volume_traite = volume_traite
        self.save()

    def noter(self, note, commentaire=''):
        if self.statut != 'TERMINEE':
            raise ValidationError("Seules les demandes terminées peuvent être notées")
        
        self.note = note
        self.commentaire = commentaire
        self.save()

    def clean(self):
        # Validation côté modèle pour la cohérence des types
        from django.core.exceptions import ValidationError as DjangoValidationError
        super().clean()
        # S'assurer que l'usager a bien le rôle USAGER
        if self.usager and self.usager.role != User.Role.USAGER:
            raise DjangoValidationError({'usager': _("L'utilisateur sélectionné doit avoir le rôle Usager")})
        if self.vidangeur:
            from .models import VidangeurMecanique, VidangeurManuel
            if self.type_vidange == 'MECANIQUE' and not isinstance(self.vidangeur, VidangeurMecanique):
                raise DjangoValidationError({'vidangeur': _("Le vidangeur doit être de type Mécanique pour une demande mécanique")})
            if self.type_vidange == 'MANUELLE' and not isinstance(self.vidangeur, VidangeurManuel):
                raise DjangoValidationError({'vidangeur': _("Le vidangeur doit être de type Manuelle pour une demande manuelle")})

class PositionGPS(models.Model):
    vidangeur = models.ForeignKey(
        Vidangeur,
        on_delete=models.CASCADE,
        related_name='positions_gps',
        verbose_name=_('vidangeur')
    )
    position = gis_models.PointField(_('position géographique'), srid=4326, default=Point(0, 0))
    timestamp = models.DateTimeField(_('horodatage'), default=timezone.now)
    date_creation = models.DateTimeField(_('date de création'), auto_now_add=True)

    class Meta:
        verbose_name = _('position GPS')
        verbose_name_plural = _('positions GPS')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['vidangeur', 'timestamp']),
        ]

    def __str__(self):
        return f"Position du {self.timestamp.strftime('%d/%m/%Y %H:%M')} - {self.vidangeur}"

    @property
    def latitude(self):
        return self.position.y if self.position else None

    @property
    def longitude(self):
        return self.position.x if self.position else None

    def set_position(self, latitude, longitude, **kwargs):
        """Définit la position avec des coordonnées GPS"""
        self.position = Point(longitude, latitude)
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

class Signalisation(models.Model):
    class TypeSignalement(models.TextChoices):
        COMPORTEMENT = 'COMPORTEMENT', _('Comportement inapproprié')
        VEHICULE = 'VEHICULE', _('Problème avec le véhicule')
        AUTRE = 'AUTRE', _('Autre problème')

    class StatutSignalement(models.TextChoices):
            EN_ATTENTE = 'EN_ATTENTE', _('En attente')
            TRAITE = 'TRAITE', _('Traité')
            REJETE = 'REJETE', _('Rejeté')

    type_signalement = models.CharField(_('type'), max_length=20, choices=TypeSignalement.choices)
    description = models.TextField(_('description'))
    immatriculation = models.CharField(_('immatriculation'), max_length=20)
    localisation = models.TextField(_('lieu'), blank=True)
    signalant_telephone = models.CharField(_('téléphone'), max_length=20)
    signalant_nom = models.CharField(_('nom'), max_length=100, blank=True)
    statut = models.CharField(
        _('statut'),
        max_length=20,
        choices=StatutSignalement.choices,
        default=StatutSignalement.EN_ATTENTE
    )
    traite_par = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={'role__in': [User.Role.ADMIN]},
        related_name='signalements_traites'
    )
    traite_le = models.DateTimeField(_('traité le'), null=True, blank=True)
    commentaire = models.TextField(_('commentaire'), blank=True)
    created_at = models.DateTimeField(_('créé le'), auto_now_add=True)
    updated_at = models.DateTimeField(_('mis à jour le'), auto_now=True)

    class Meta:
        verbose_name = _('signalisation')
        verbose_name_plural = _('signalisation')
        ordering = ['-created_at']

    def __str__(self):
        return f"Signalement #{self.id} - {self.get_type_signalement_display()}"

class Notification(models.Model):
    class TypeNotification(models.TextChoices):
        DEMANDE_RECUE = 'DEMANDE_RECUE', _('Nouvelle demande reçue')
        DEMANDE_ACCEPTEE = 'DEMANDE_ACCEPTEE', _('Demande acceptée')
        DEMANDE_REFUSEE = 'DEMANDE_REFUSEE', _('Demande refusée')
        CHAUFFEUR_EN_ROUTE = 'CHAUFFEUR_EN_ROUTE', _('Chauffeur en route')
        CHAUFFEUR_ARRIVE = 'CHAUFFEUR_ARRIVE', _('Chauffeur arrivé')
        SERVICE_TERMINE = 'SERVICE_TERMINE', _('Service terminé')
        NOUVELLE_DEMANDE = 'NOUVELLE_DEMANDE', _('Nouvelle demande disponible')
        ANNULATION = 'ANNULATION', _('Annulation de service')

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    type_notification = models.CharField(
        _('type'),
        max_length=20,
        choices=TypeNotification.choices
    )
    titre = models.CharField(_('titre'), max_length=100)
    message = models.TextField(_('message'))
    lue = models.BooleanField(_('lue'), default=False)
    donnees = models.JSONField(_('données'), default=dict, blank=True)
    created_at = models.DateTimeField(_('créée le'), auto_now_add=True)

    class Meta:
        verbose_name = _('notification')
        verbose_name_plural = _('notifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'lue']),
        ]

    def __str__(self):
        return f"Notification pour {self.user}: {self.titre}"

class Device(models.Model):
    class Platform(models.TextChoices):
        ANDROID = 'ANDROID', _('Android')
        IOS = 'IOS', _('iOS')
        WEB = 'WEB', _('Web')

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='devices',
        verbose_name=_('utilisateur')
    )
    token = models.CharField(_('token FCM'), max_length=255, unique=True)
    platform = models.CharField(_('plateforme'), max_length=10, choices=Platform.choices)
    app_version = models.CharField(_('version app'), max_length=50, blank=True, null=True)
    is_active = models.BooleanField(_('actif'), default=True)
    last_seen = models.DateTimeField(_('dernier contact'), default=timezone.now)
    created_at = models.DateTimeField(_('créé le'), auto_now_add=True)
    updated_at = models.DateTimeField(_('mis à jour le'), auto_now=True)

    class Meta:
        verbose_name = _('appareil')
        verbose_name_plural = _('appareils')
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
        ]

    def __str__(self):
        return f"{self.platform} - {self.user.phone_number}"