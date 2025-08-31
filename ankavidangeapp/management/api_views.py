from django.http import JsonResponse
from django.views import View
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q
from django.core.serializers.json import DjangoJSONEncoder
import json
from django.urls import reverse_lazy

from ankavidangeapp.models import Vidangeur, VidangeurMecanique, PositionGPS, Demande
from django.contrib.auth import get_user_model

User = get_user_model()

class StaffRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Mixin to ensure user is staff."""
    login_url = reverse_lazy('staff_login')
    def test_func(self):
        return self.request.user.is_staff

class TruckPositionAPIView(StaffRequiredMixin, View):
    """API endpoint to get current truck positions."""
    
    def get(self, request, *args, **kwargs):
        # Get all active vidangeurs
        trucks = Vidangeur.objects.filter(actif=True).prefetch_related('positions_gps')
        
        # Get the latest position for each truck
        truck_data = []
        for truck in trucks:
            latest_position = truck.positions_gps.order_by('-timestamp').first()
            
            # Determine status based on last update time or other criteria
            status = 'unavailable'
            status_display = 'Indisponible'
            
            if latest_position:
                time_since_update = timezone.now() - latest_position.timestamp
                
                if time_since_update < timedelta(hours=1):  # Considered recent
                    if truck.statut == 'EN_MISSION':
                        status = 'on_mission'
                        status_display = 'En mission'
                    elif truck.statut == 'DISPONIBLE':
                        status = 'available'
                        status_display = 'Disponible'
            
            truck_data.append({
                'id': truck.id,
                'immatriculation': truck.immatriculation,
                'modele': truck.modele,
                'status': status,
                'status_display': status_display,
                'latitude': float(latest_position.latitude) if latest_position else None,
                'longitude': float(latest_position.longitude) if latest_position else None,
                'last_update': latest_position.timestamp.strftime('%d/%m/%Y %H:%M') if latest_position else 'Jamais',
                'timestamp': latest_position.timestamp.isoformat() if latest_position else None
            })
        
        return JsonResponse({'trucks': truck_data}, encoder=DjangoJSONEncoder)


class RequestStatsAPIView(StaffRequiredMixin, View):
    """API endpoint to get request statistics for charts."""
    
    def get(self, request, *args, **kwargs):
        # Get date range (default: last 7 days)
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=6)  # 7 days total including today
        
        # Initialize date range
        date_range = [start_date + timedelta(days=x) for x in range((end_date - start_date).days + 1)]
        
        # Get daily request counts
        daily_counts = Demande.objects.filter(
            date_creation__date__range=[start_date, end_date]
        ).values('date_creation__date').annotate(
            count=Count('id')
        ).order_by('date_creation__date')
        
        # Create a dictionary of date: count
        count_dict = {item['date_creation__date']: item['count'] for item in daily_counts}
        
        # Fill in missing dates with 0
        daily_data = [count_dict.get(date, 0) for date in date_range]
        
        # Format dates for display
        date_labels = [date.strftime('%a %d/%m') for date in date_range]
        
        # Get status counts
        status_counts = Demande.objects.values('statut').annotate(
            count=Count('id')
        ).order_by('statut')
        
        # Prepare data for charts
        chart_data = {
            'daily': {
                'labels': date_labels,
                'data': daily_data,
            },
            'status': {
                'labels': [dict(Demande.STATUT_CHOICES).get(item['statut'], item['statut']) 
                          for item in status_counts],
                'data': [item['count'] for item in status_counts],
                'background_colors': [
                    '#1cc88a',  # Success green
                    '#f6c23e',  # Warning yellow
                    '#e74a3b',  # Danger red
                    '#4e73df',  # Primary blue
                    '#858796',  # Secondary gray
                ]
            }
        }
        
        return JsonResponse(chart_data, encoder=DjangoJSONEncoder)
