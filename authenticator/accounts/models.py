from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext as _
from django.utils import timezone
from django.utils.crypto import get_random_string

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUserProfile(AbstractUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_confirmed = models.BooleanField(default=False, verbose_name=_('Email Confirmed'))
    email_confirmation_code = models.CharField(max_length=255, null=True, blank=True, verbose_name=_('Email Confirmation Code'))
    email_verification_code = models.CharField(max_length=6, null=True, blank=True, verbose_name=_('verification code'))

    
    username = models.CharField(max_length=30, unique=True)


    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    
class EmailConfirmation(models.Model):
    user = models.OneToOneField(CustomUserProfile, on_delete=models.CASCADE, related_name='email_confirmation')
    code = models.CharField(max_length=255, verbose_name=_('Confirmation Code'))

    def __str__(self):
        return f"Email Confirmation for {self.user.username}"
    
class EmailConfirmationManager(models.Manager):
    def create_confirmation(self, user):
        code = get_random_string(length=6)  # Generate a 6-digit code
        return self.create(user=user, code=code, created_at=timezone.now())

    def verify_confirmation(self, user, code):
        confirmation = self.filter(user=user, code=code).first()
        if confirmation and not confirmation.is_expired():
            confirmation.delete()
            return True
        return False
