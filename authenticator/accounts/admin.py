from django.contrib import admin
from django.contrib.auth import get_user_model
from django.http.request import HttpRequest
from django.utils.translation import gettext_lazy as _
from authemail.admin import EmailUserAdmin
from .models import VerifiedUserProfile

class AdminProfile(EmailUserAdmin):
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'is_verified', 'groups',
                                       'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
class VerifiedAdminProfile(AdminProfile):
    def has_add_permission(self, request):
        return False
    
    
admin.site.unregister(get_user_model())
admin.site.register(get_user_model(), AdminProfile)
admin.site.register(VerifiedUserProfile, VerifiedAdminProfile)