from django.urls import path
from . import views

app_name = 'management'

urlpatterns = [
    # Dashboard
    path('', views.DashboardView.as_view(), name='dashboard'),

    # Truck Management
    path('truck-map/', views.TruckMapView.as_view(), name='truck_map'),
    
    # Reports
    path('reports/', views.ReportsView.as_view(), name='reports'),
    
    # User Management
    path('users/', views.UserManagementView.as_view(), name='user_management'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('users/add/', views.UserCreateView.as_view(), name='user_add'),
    path('users/<int:pk>/edit/', views.UserUpdateView.as_view(), name='user_edit'),
    path('users/<int:pk>/delete/', views.UserDeleteView.as_view(), name='user_delete'),

    # Tariffs
    path('tarifs/', views.TarifsListView.as_view(), name='tarifs_list'),
    path('tarifs/new/', views.TarifsCreateView.as_view(), name='tarifs_create'),
    # Vidangeur tarifs management
    path('vidangeurs/<int:pk>/tarifs/', views.VidangeurTarifsView.as_view(), name='vidangeur_tarifs'),
    
    # Centres de vidange
    path('centres/', views.CentreListView.as_view(), name='centres_list'),
    
    # Request Follow-up
    path('requests/', views.RequestFollowUpView.as_view(), name='request_followup'),
    path('requests/<int:pk>/', views.RequestDetailView.as_view(), name='request_detail'),
    path('requests/<int:pk>/update-status/', 
         views.update_request_status, 
         name='update_request_status'),
    path('requests/<int:pk>/delete/', 
         views.delete_request, 
         name='request_delete'),
]
