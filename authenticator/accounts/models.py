from django.db import models
from django.db.models.query import QuerySet
from django.utils.translation import gettext_lazy as _
from authemail.models import EmailAbstractUser, EmailUserManager

class UserProfile(EmailAbstractUser):
    
    objects = EmailUserManager()
    
class VerifiedUserManager(EmailUserManager):
    def get_queryset(self):
        return super(VerifiedUserManager, self).get_queryset().filter(
            is_verified=True
        )
        
class VerifiedUserProfile(UserProfile):
    objects = VerifiedUserManager()
    
    class Meta:
        proxy = True
    