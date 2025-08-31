from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from ankavidangeapp.management import views as management_views

admin.site.site_header = 'Anka Vidange Administration'
admin.site.index_title = 'Bienvenue sur Anka Vidange Administration'
admin.site.site_title = 'Anka Vidange Administration'

urlpatterns = [
    # Admin site
    # path('admin/', admin.site.urls),
    
    # Management dashboard - separate from default admin
    path('staff/login/', management_views.LoginView.as_view(template_name='management/login.html'), name='staff_login'),
    path('staff/logout/', management_views.LogoutView.as_view(), name='staff_logout'),
    path('management/', include(('ankavidangeapp.management.urls', 'management'), namespace='management')),
    

    # Main application URLs
    path('', include('ankavidangeapp.urls')),

    # API URLs
    path('api/', include('ankavidangeapp.api.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)