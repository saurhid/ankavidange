from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, RefreshToken
from rest_framework_simplejwt.settings import api_settings
from django.utils import timezone
from ..models import Vidangeur, VidangeurMecanique, VidangeurManuel, Demande, Device, Proprietaire
from django.db.models import Min
from decimal import Decimal

User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'phone_number'
    
    def validate(self, attrs):
        attrs['username'] = attrs.get('phone_number', '')
        data = super().validate(attrs)
        
        refresh = self.get_token(self.user)
        data['user'] = {
            'id': self.user.id,
            'phone_number': self.user.phone_number,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'role': self.user.role,
            'is_active': self.user.is_active
        }
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        
        return data

class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)

    def validate(self, attrs):
        refresh = attrs.get('refresh')
        
        if not refresh:
            raise serializers.ValidationError({
                'error': 'Le refresh token est requis',
                'code': 'missing_refresh_token'
            })
            
        try:
            refresh_token = RefreshToken(refresh)
            data = {'access': str(refresh_token.access_token)}
            
            if api_settings.ROTATE_REFRESH_TOKENS:
                if api_settings.BLACKLIST_AFTER_ROTATION:
                    try:
                        refresh_token.blacklist()
                    except AttributeError:
                        pass
                
                refresh_token.set_jti()
                refresh_token.set_exp()
                data['refresh'] = str(refresh_token)
            
            return data
            
        except Exception:
            raise serializers.ValidationError({
                'error': 'Token invalide ou expiré',
                'code': 'token_invalid'
            })

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'first_name', 'last_name', 'role', 'is_active', 'date_joined']
        read_only_fields = ['id', 'is_active', 'date_joined', 'role']

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['phone_number', 'password', 'password2', 'first_name', 'last_name']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password2'):
            raise serializers.ValidationError({"password": "Les mots de passe ne correspondent pas."})
        return attrs

    def create(self, validated_data):
        # Force default role to USAGER for public registration
        user = User.objects.create_user(
            phone_number=validated_data['phone_number'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=User.Role.USAGER,
        )
        return user

class PositionCreateSerializer(serializers.Serializer):
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()
    timestamp = serializers.DateTimeField(required=False)

    def validate(self, attrs):
        lat = attrs.get('latitude')
        lon = attrs.get('longitude')
        if not (-90 <= lat <= 90):
            raise serializers.ValidationError({'latitude': 'Latitude must be between -90 and 90'})
        if not (-180 <= lon <= 180):
            raise serializers.ValidationError({'longitude': 'Longitude must be between -180 and 180'})
        return attrs

class VidangeurStatusSerializer(serializers.Serializer):
    # Accept both 'status' and 'statut' to support different client payloads
    status = serializers.ChoiceField(choices=[c[0] for c in Vidangeur.STATUT_CHOICES], required=False)
    statut = serializers.ChoiceField(choices=[c[0] for c in Vidangeur.STATUT_CHOICES], required=False)

    def validate(self, attrs):
        value = attrs.get('status') or attrs.get('statut')
        if not value:
            raise serializers.ValidationError({'status': "Field required: provide 'status' or 'statut' with one of: " + ', '.join([c[0] for c in Vidangeur.STATUT_CHOICES])})
        # Normalize to 'status'
        attrs['status'] = value
        attrs.pop('statut', None)
        return attrs

class VidangeurProfileSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    user = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    statut = serializers.CharField()
    actif = serializers.BooleanField()
    latitude = serializers.FloatField( allow_null=True)
    longitude = serializers.FloatField( allow_null=True)

    # Mechanical-specific
    immatriculation = serializers.CharField(required=False, allow_null=True)
    marque = serializers.CharField(required=False, allow_null=True)
    modele = serializers.CharField(required=False, allow_null=True)
    annee = serializers.IntegerField(required=False, allow_null=True)
    capacite = serializers.IntegerField(required=False, allow_null=True)

    # Manual-specific
    tarif_manuel = serializers.DecimalField(required=False, allow_null=True, max_digits=10, decimal_places=2)

    def get_user(self, obj):
        u = obj.user
        return {
            'id': u.id,
            'full_name': u.get_full_name(),
            'phone_number': u.phone_number,
        }

    def get_type(self, obj):
        if isinstance(obj, VidangeurMecanique):
            return 'MECANIQUE'
        if isinstance(obj, VidangeurManuel):
            return 'MANUELLE'
        return 'INCONNU'

    def to_representation(self, obj):
        data = super().to_representation(obj)
        # Remove irrelevant subtype fields
        if isinstance(obj, VidangeurMecanique):
            data.pop('tarif_manuel', None)
        if isinstance(obj, VidangeurManuel):
            for f in ['immatriculation', 'marque', 'modele', 'annee', 'capacite']:
                data.pop(f, None)
        return data

class DemandeSerializer(serializers.ModelSerializer):
    usager_name = serializers.SerializerMethodField()
    usager_phone = serializers.SerializerMethodField()
    latitude = serializers.SerializerMethodField()
    longitude = serializers.SerializerMethodField()

    class Meta:
        model = Demande
        fields = [
            'id', 'reference', 'statut', 'type_vidange', 'adresse', 'date_demande',
            'date_debut_intervention', 'date_fin_intervention', 'usager_name', 'usager_phone', 'latitude', 'longitude'
        ]
        read_only_fields = fields

    def get_usager_name(self, obj):
        return obj.usager.get_full_name() if obj.usager else None

    def get_usager_phone(self, obj):
        return getattr(obj.usager, 'phone_number', None) if obj.usager else None

    def get_latitude(self, obj):
        return obj.latitude

    def get_longitude(self, obj):
        return obj.longitude

class VidangeurSearchResultSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    phone = serializers.CharField()
    type = serializers.ChoiceField(choices=[('MECANIQUE','MECANIQUE'), ('MANUELLE','MANUELLE')])
    price = serializers.DecimalField(max_digits=10, decimal_places=2)
    statut = serializers.CharField(required=False, allow_blank=True)
    capacity = serializers.IntegerField(required=False, allow_null=True)

class DemandeCreateSerializer(serializers.Serializer):
    adresse = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    type_vidange = serializers.ChoiceField(choices=[c[0] for c in Demande.TYPE_VIDANGE_CHOICES])
    volume_estime = serializers.ChoiceField(choices=[c[0] for c in Demande.TYPE_FOSSE_CHOICES])
    budget = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    date_souhaitee = serializers.DateTimeField(required=False, allow_null=True)
    commentaire = serializers.CharField(required=False, allow_blank=True)
    vidangeur_id = serializers.IntegerField()
    latitude = serializers.FloatField(required=False, allow_null=True)
    longitude = serializers.FloatField(required=False, allow_null=True)

    def validate(self, attrs):
        # Require either a non-empty address or both coordinates
        adresse = (attrs.get('adresse') or '').strip()
        lat = attrs.get('latitude')
        lng = attrs.get('longitude')
        if not adresse:
            if lat is None or lng is None:
                raise serializers.ValidationError({'adresse': "Fournissez une adresse ou bien sélectionnez un point sur la carte (latitude/longitude)."})
        else:
            # If adresse provided but one of lat/lng provided alone, enforce both
            if (lat is not None and lng is None) or (lng is not None and lat is None):
                raise serializers.ValidationError({'latitude': 'Latitude et Longitude doivent être fournies ensemble.'})
        # Basic sanity checks
        if lat is not None and not (-90 <= float(lat) <= 90):
            raise serializers.ValidationError({'latitude': 'Latitude must be between -90 and 90'})
        if lng is not None and not (-180 <= float(lng) <= 180):
            raise serializers.ValidationError({'longitude': 'Longitude must be between -180 and 180'})
        return attrs

class FCMRegisterSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    platform = serializers.ChoiceField(choices=Device.Platform.choices)
    app_version = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate_token(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError('Token FCM invalide')
        return value

class FCMTokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)

class NotificationTestSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=100, required=False, default='Test notification')
    body = serializers.CharField(max_length=255, required=False, default='Bonjour depuis Allo-vidange')
    data = serializers.DictField(child=serializers.CharField(), required=False, default=dict)

class OwnerTruckSerializer(serializers.ModelSerializer):
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    phone_number = serializers.CharField(source='user.phone_number', read_only=True)
    latitude = serializers.FloatField(read_only=True)
    longitude = serializers.FloatField(read_only=True)

    class Meta:
        model = VidangeurMecanique
        fields = [
            'id', 'immatriculation', 'marque', 'modele', 'annee', 'capacite',
            'statut', 'actif', 'latitude', 'longitude', 'user_full_name', 'phone_number'
        ]
        read_only_fields = fields

class OwnerDemandeSerializer(serializers.ModelSerializer):
    usager_name = serializers.SerializerMethodField()
    vidangeur_id = serializers.IntegerField(source='vidangeur.id', read_only=True)
    vidangeur_name = serializers.SerializerMethodField()

    class Meta:
        model = Demande
        fields = [
            'id', 'reference', 'statut', 'type_vidange', 'adresse', 'date_demande',
            'date_debut_intervention', 'date_fin_intervention', 'budget', 'usager_name', 'vidangeur_id', 'vidangeur_name'
        ]
        read_only_fields = fields

    def get_usager_name(self, obj):
        return obj.usager.get_full_name() if obj.usager else None

    def get_vidangeur_name(self, obj):
        if obj.vidangeur and obj.vidangeur.user:
            return obj.vidangeur.user.get_full_name()
        return None

class OwnerProfileSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Proprietaire
        fields = [
            'user',
            'nom_societe',
            'contact',
            'type',
            'numero_agrement',
            'verification_status',
            'date_verification',
            'notes_verification',
        ]
        read_only_fields = fields

    def get_user(self, obj):
        u = obj.user
        return {
            'id': u.id,
            'phone_number': u.phone_number,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'full_name': f"{u.first_name} {u.last_name}".strip(),
            'role': u.role,
            'date_joined': u.date_joined,
        }
