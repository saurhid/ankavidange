from rest_framework import viewsets, permissions, status, filters, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta
from django.db import transaction
from django.shortcuts import get_object_or_404

from django_filters import rest_framework as django_filters

from ..models import (
    User, 
    Vidangeur,
    VidangeurMecanique,
    VidangeurManuel,
    PositionGPS,
    Demande,
    CentreVidange,
    Device
)
from ..api.serializers import (
    CustomTokenObtainPairSerializer, 
    TokenRefreshSerializer,
    UserSerializer, 
    UserCreateSerializer, 
    PositionCreateSerializer,
    VidangeurStatusSerializer,
    VidangeurProfileSerializer,
    DemandeSerializer,
    VidangeurSearchResultSerializer,
    DemandeCreateSerializer,
    FCMRegisterSerializer,
    FCMTokenSerializer,
    NotificationTestSerializer,
)

from rest_framework.parsers import JSONParser, FormParser, MultiPartParser

from django.conf import settings
from django.db.models import Min, Q

# Firebase Admin lazy init
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    if not firebase_admin._apps:
        cred_path = getattr(settings, 'FIREBASE_CREDENTIALS_PATH', None)
        if cred_path:
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        else:
            # Will use ADC if available
            firebase_admin.initialize_app()
    _fcm_ready = True
except Exception:
    firebase_admin = None
    messaging = None
    _fcm_ready = False

class APiRegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = UserCreateSerializer

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data,
            context=self.get_serializer_context()
        )
        if serializer.is_valid():
            user = serializer.save()

            refresh = RefreshToken.for_user(user)
            
            response_data = {
                'user': UserSerializer(user, context=self.get_serializer_context()).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        return Response({
            'message': 'Utilisez la méthode POST pour enregistrer un nouvel utilisateur',
            'required_fields': {
                'phone_number': 'string (format: XXXXXXXX)',
                'password': 'string',
                'password2': 'string (must match password)',
                'first_name': 'string',
                'last_name': 'string',
                'user_type': 'USAGER'
            }
        })

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        if 'phone_number' not in request.data:
            return Response(
                {'error': 'Le phone_number est requis'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().post(request, *args, **kwargs)

class TokenRefreshView(APIView):
    permission_classes = [AllowAny]
    serializer_class = TokenRefreshSerializer
    
    def post(self, request, *args, **kwargs):
        
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response(
                {'error': 'Could not refresh token'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [django_filters.DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    search_fields = ['phone_number', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'last_login']
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer
    
    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAuthenticated()]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        # If user is not admin, only allow viewing their own profile
        if not self.request.user.is_staff:
            return queryset.filter(id=self.request.user.id)
        return queryset

class VidangeursPositionsAPIView(APIView):
    """API endpoint to get all vidangeurs positions for landing page map."""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        vidangeurs_data = []
        
        # Get mechanical vidangeurs with positions
        for vidangeur in VidangeurMecanique.objects.filter(actif=True).select_related('user'):
            latest_position = vidangeur.positions_gps.order_by('-timestamp').first()
            if latest_position:
                # Check if position is recent (within last 24 hours)
                is_recent = timezone.now() - latest_position.timestamp < timedelta(hours=24)
                
                vidangeurs_data.append({
                    'id': vidangeur.id,
                    'name': vidangeur.user.get_full_name(),
                    'phone': vidangeur.user.phone_number,
                    'type': 'mecanique',
                    'icon': 'truck-solid',
                    'latitude': float(latest_position.latitude),
                    'longitude': float(latest_position.longitude),
                    'last_update': latest_position.timestamp.strftime('%d/%m/%Y %H:%M'),
                    'is_recent': is_recent,
                    'status': vidangeur.statut if hasattr(vidangeur, 'statut') else 'DISPONIBLE'
                })
        
        # Get manual vidangeurs with positions
        for vidangeur in VidangeurManuel.objects.filter(actif=True).select_related('user'):
            latest_position = vidangeur.positions_gps.order_by('-timestamp').first()
            if latest_position:
                # Check if position is recent (within last 24 hours)
                is_recent = timezone.now() - latest_position.timestamp < timedelta(hours=24)
                
                vidangeurs_data.append({
                    'id': vidangeur.id,
                    'name': vidangeur.user.get_full_name(),
                    'phone': vidangeur.user.phone_number,
                    'type': 'manuelle',
                    'icon': 'tools',
                    'latitude': float(latest_position.latitude),
                    'longitude': float(latest_position.longitude),
                    'last_update': latest_position.timestamp.strftime('%d/%m/%Y %H:%M'),
                    'is_recent': is_recent,
                    'status': vidangeur.statut if hasattr(vidangeur, 'statut') else 'DISPONIBLE'
                })
        
        return Response({
            'vidangeurs': vidangeurs_data,
            'total_count': len(vidangeurs_data)
        })

class CentresPositionsAPIView(APIView):
    """API endpoint to get all active centres positions for map display."""
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        centres_data = []
        centres = CentreVidange.objects.filter(actif=True).order_by('nom')
        for centre in centres:
            if centre.position:
                centres_data.append({
                    'id': centre.id,
                    'name': centre.nom,
                    'latitude': float(centre.latitude),
                    'longitude': float(centre.longitude),
                })
        return Response({
            'centres': centres_data,
            'total_count': len(centres_data)
        })

class PositionCreateAPIView(APIView):
    """Create a GPS position for the authenticated vidangeur."""
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Validate payload
        serializer = PositionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user: User = request.user
        # Ensure user is a vidangeur (either mec or man)
        if user.role not in [User.Role.VIDANGEUR_MEC, User.Role.VIDANGEUR_MAN]:
            return Response({'detail': 'Seuls les vidangeurs peuvent publier leur position.'}, status=status.HTTP_403_FORBIDDEN)

        # Get base Vidangeur from current user
        try:
            vidangeur = Vidangeur.objects.select_related('user').get(user=user)
        except Vidangeur.DoesNotExist:
            return Response({'detail': "Profil vidangeur introuvable pour cet utilisateur."}, status=status.HTTP_400_BAD_REQUEST)

        # Create PositionGPS
        pos = PositionGPS(vidangeur=vidangeur)
        ts = data.get('timestamp') or timezone.now()
        # set_position will build the Point and also accept extra fields
        pos.set_position(latitude=data['latitude'], longitude=data['longitude'], timestamp=ts)
        pos.save()

        # Update current position on vidangeur for quick access
        try:
            vidangeur.mettre_a_jour_position(data['latitude'], data['longitude'])
        except Exception:
            # Non-fatal if update fails
            pass

        return Response({
            'id': pos.id,
            'vidangeur_id': vidangeur.id,
            'latitude': float(pos.latitude) if pos.latitude is not None else None,
            'longitude': float(pos.longitude) if pos.longitude is not None else None,
            'timestamp': pos.timestamp.isoformat(),
        }, status=status.HTTP_201_CREATED)

class IsVidangeur(permissions.BasePermission):
    """Allow only authenticated users with Vidangeur role (mec or man)."""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.role in [User.Role.VIDANGEUR_MEC, User.Role.VIDANGEUR_MAN]

def _get_vidangeur_for_user(user: User) -> Vidangeur:
    """Return the vidangeur instance, downcasted to subtype if applicable."""
    base = get_object_or_404(Vidangeur.objects.select_related('user'), user=user)
    # Try to downcast to concrete subclass
    mec = VidangeurMecanique.objects.filter(pk=base.pk).first()
    if mec:
        return mec
    man = VidangeurManuel.objects.filter(pk=base.pk).first()
    if man:
        return man
    return base

class VidangeurStatusView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def put(self, request, *args, **kwargs):
        serializer = VidangeurStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            vid = _get_vidangeur_for_user(request.user)
        except Exception:
            return Response({'detail': "Profil vidangeur introuvable pour cet utilisateur."}, status=status.HTTP_400_BAD_REQUEST)
        new_status = serializer.validated_data['status']
        vid.statut = new_status
        vid.save(update_fields=['statut', 'date_maj'])
        return Response({'id': vid.id, 'statut': vid.statut, 'updated_at': timezone.now().isoformat()})

    # Allow POST as an alias of PUT for clients that cannot send PUT
    def post(self, request, *args, **kwargs):
        return self.put(request, *args, **kwargs)

class VidangeurProfileView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def get(self, request, *args, **kwargs):
        try:
            vid = _get_vidangeur_for_user(request.user)
        except Exception:
            return Response({'detail': "Profil vidangeur introuvable pour cet utilisateur."}, status=status.HTTP_400_BAD_REQUEST)
        data = VidangeurProfileSerializer(vid).data
        return Response(data)

class AcceptedDemandsView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]

    def get(self, request, *args, **kwargs):
        vid = _get_vidangeur_for_user(request.user)
        qs = Demande.objects.filter(vidangeur=vid, statut='EN_COURS')
        include = request.query_params.get('include')
        if include and include.upper() == 'VALIDE':
            qs = Demande.objects.filter(vidangeur=vid, statut__in=['EN_COURS', 'VALIDE'])
        data = DemandeSerializer(qs.order_by('-date_demande'), many=True).data
        return Response({'count': len(data), 'results': data})

class AcceptDemandView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]

    @transaction.atomic
    def post(self, request, pk: int, *args, **kwargs):
        vid = _get_vidangeur_for_user(request.user)
        demande = get_object_or_404(Demande.objects.select_for_update(), pk=pk)
        if demande.statut != 'EN_ATTENTE':
            return Response({'detail': "Cette demande ne peut pas être acceptée."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            demande.accepter_par(vid)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        # Optionally set vidangeur status to EN_MISSION
        vid.statut = 'EN_MISSION'
        vid.save(update_fields=['statut', 'date_maj'])
        return Response(DemandeSerializer(demande).data, status=status.HTTP_200_OK)

class CompleteDemandView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]

    @transaction.atomic
    def post(self, request, pk: int, *args, **kwargs):
        vid = _get_vidangeur_for_user(request.user)
        demande = get_object_or_404(Demande.objects.select_for_update(), pk=pk)
        if demande.vidangeur_id != vid.id:
            return Response({'detail': "Vous n'êtes pas assigné à cette demande."}, status=status.HTTP_403_FORBIDDEN)
        volume = request.data.get('volume_traite')
        try:
            demande.terminer(volume)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        # Set vidangeur back to DISPONIBLE
        vid.statut = 'DISPONIBLE'
        vid.save(update_fields=['statut', 'date_maj'])
        return Response(DemandeSerializer(demande).data, status=status.HTTP_200_OK)

class CancelDemandView(APIView):
    permission_classes = [IsAuthenticated, IsVidangeur]

    @transaction.atomic
    def post(self, request, pk: int, *args, **kwargs):
        vid = _get_vidangeur_for_user(request.user)
        demande = get_object_or_404(Demande.objects.select_for_update(), pk=pk)
        if demande.vidangeur_id != vid.id:
            return Response({'detail': "Vous n'êtes pas assigné à cette demande."}, status=status.HTTP_403_FORBIDDEN)
        if demande.statut not in ['EN_ATTENTE', 'EN_COURS', 'VALIDE']:
            return Response({'detail': "Cette demande ne peut pas être annulée."}, status=status.HTTP_400_BAD_REQUEST)
        # Cancel
        demande.statut = 'ANNULEE'
        if demande.date_debut_intervention and not demande.date_fin_intervention:
            demande.date_fin_intervention = timezone.now()
        demande.save(update_fields=['statut', 'date_fin_intervention', 'date_maj'])
        # Set vidangeur back to DISPONIBLE if he was on mission
        if hasattr(vid, 'statut') and vid.statut == 'EN_MISSION':
            vid.statut = 'DISPONIBLE'
            vid.save(update_fields=['statut', 'date_maj'])
        return Response(DemandeSerializer(demande).data, status=status.HTTP_200_OK)

class FCMRegisterView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = FCMRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']
        platform = serializer.validated_data['platform']
        app_version = serializer.validated_data.get('app_version')

        device, created = Device.objects.update_or_create(
            token=token,
            defaults={
                'user': request.user,
                'platform': platform,
                'app_version': app_version,
                'is_active': True,
                'last_seen': timezone.now(),
            }
        )
        # Optional: clear legacy single token on user model
        if not request.user.fcm_token:
            try:
                request.user.fcm_token = token
                request.user.save(update_fields=['fcm_token'])
            except Exception:
                pass
        return Response({'registered': True, 'created': created}, status=status.HTTP_200_OK)

class FCMUnregisterView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = FCMTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']
        Device.objects.filter(token=token, user=request.user).update(is_active=False)
        # Also remove from legacy field if matches
        if request.user.fcm_token == token:
            request.user.fcm_token = None
            request.user.save(update_fields=['fcm_token'])
        return Response({'unregistered': True}, status=status.HTTP_200_OK)

class FCMTestView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = NotificationTestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        title = serializer.validated_data['title']
        body = serializer.validated_data['body']
        data = serializer.validated_data.get('data') or {}

        tokens = list(Device.objects.filter(user=request.user, is_active=True).values_list('token', flat=True))
        if not tokens:
            return Response({'detail': 'Aucun appareil enregistré.'}, status=status.HTTP_400_BAD_REQUEST)

        if not _fcm_ready:
            # Simulate success in non-configured environments
            return Response({'sent': False, 'detail': 'FCM non initialisé côté serveur. Configurez FIREBASE_CREDENTIALS_PATH.', 'tokens': len(tokens)}, status=status.HTTP_200_OK)

        # Send multicast
        message = messaging.MulticastMessage(
            notification=messaging.Notification(title=title, body=body),
            data={str(k): str(v) for k, v in (data or {}).items()},
            tokens=tokens,
        )
        response_msg = messaging.send_multicast(message)

        # Deactivate invalid tokens
        deactivated = 0
        for idx, resp in enumerate(response_msg.responses):
            if not resp.success:
                err = getattr(resp.exception, 'code', '')
                if err in ('registration-token-not-registered', 'invalid-argument'):
                    Device.objects.filter(token=tokens[idx]).update(is_active=False)
                    deactivated += 1

        return Response({'sent': True, 'success_count': response_msg.success_count, 'failure_count': response_msg.failure_count, 'deactivated': deactivated}, status=status.HTTP_200_OK)

class SearchVidangeursView(APIView):
    """Search vidangeurs by type and max budget."""
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication, SessionAuthentication]

    def get(self, request, *args, **kwargs):
        type_vidange = request.query_params.get('type_vidange')
        max_budget = request.query_params.get('budget')
        results = []

        if type_vidange not in ['MECANIQUE', 'MANUELLE']:
            return Response({'detail': "Paramètre 'type_vidange' invalide"}, status=status.HTTP_400_BAD_REQUEST)

        # Manual vidangeurs
        if type_vidange == 'MANUELLE':
            qs = VidangeurManuel.objects.filter(actif=True).select_related('user')
            if max_budget:
                try:
                    max_b = float(max_budget)
                    qs = qs.filter(tarif_manuel__lte=max_b)
                except ValueError:
                    return Response({'detail': "Budget invalide"}, status=status.HTTP_400_BAD_REQUEST)
            for v in qs:
                results.append({
                    'id': v.id,
                    'name': v.user.get_full_name(),
                    'phone': v.user.phone_number,
                    'type': 'MANUELLE',
                    'price': v.tarif_manuel,
                    'statut': getattr(v, 'statut', ''),
                })

        # Mechanical vidangeurs: use minimal price across centres
        if type_vidange == 'MECANIQUE':
            qs = VidangeurMecanique.objects.filter(actif=True).select_related('user').annotate(
                min_price=Min('tarifs_centres__prix')
            )
            if max_budget:
                try:
                    max_b = float(max_budget)
                    qs = qs.filter(min_price__isnull=False, min_price__lte=max_b)
                except ValueError:
                    return Response({'detail': "Budget invalide"}, status=status.HTTP_400_BAD_REQUEST)
            for v in qs:
                if v.min_price is None:
                    continue
                results.append({
                    'id': v.id,
                    'name': v.user.get_full_name(),
                    'phone': v.user.phone_number,
                    'type': 'MECANIQUE',
                    'price': v.min_price,
                    'statut': getattr(v, 'statut', ''),
                    'capacity': v.capacite,
                })

        data = VidangeurSearchResultSerializer(results, many=True).data
        return Response({'count': len(data), 'results': data}, status=status.HTTP_200_OK)

class DemandeCreateView(APIView):
    """Create a demande for a selected vidangeur with provided fields."""
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication, SessionAuthentication]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user: User = request.user
        if user.role != User.Role.USAGER:
            return Response({'detail': "Seuls les usagers peuvent créer une demande."}, status=status.HTTP_403_FORBIDDEN)

        serializer = DemandeCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Get vidangeur and normalize subtype
        try:
            base = Vidangeur.objects.select_related('user').get(pk=data['vidangeur_id'])
        except Vidangeur.DoesNotExist:
            return Response({'detail': "Vidangeur introuvable"}, status=status.HTTP_400_BAD_REQUEST)

        mec = VidangeurMecanique.objects.filter(pk=base.pk).first()
        man = VidangeurManuel.objects.filter(pk=base.pk).first()
        vid = mec or man or base

        # Validate type coherence
        if data['type_vidange'] == 'MECANIQUE' and not mec:
            return Response({'detail': "Le vidangeur sélectionné n'est pas de type mécanique."}, status=status.HTTP_400_BAD_REQUEST)
        if data['type_vidange'] == 'MANUELLE' and not man:
            return Response({'detail': "Le vidangeur sélectionné n'est pas de type manuelle."}, status=status.HTTP_400_BAD_REQUEST)

        demande = Demande(
            usager=user,
            type_vidange=data['type_vidange'],
            adresse=data['adresse'],
            volume_estime=data['volume_estime'],
            budget=data.get('budget'),
            date_souhaitee=data.get('date_souhaitee') or timezone.now(),
            commentaire=data.get('commentaire', ''),
            vidangeur=vid,
            statut='EN_ATTENTE',
        )
        demande.full_clean(exclude=None)
        demande.save()
        return Response(DemandeSerializer(demande).data, status=status.HTTP_201_CREATED)
