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
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_confirmed = models.BooleanField(default=False, verbose_name=_('Email Confirmed'))
    email_verification_code = models.CharField(max_length=6, null=True, blank=True, verbose_name=_('Verification code'))

    
    username = models.CharField(max_length=30)


    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    
class EmailConfirmation(models.Model):
    user = models.OneToOneField(CustomUserProfile, on_delete=models.CASCADE, related_name='email_confirmation')
    code = models.CharField(max_length=6, verbose_name=_('Confirmation Code'), unique=True)
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_('Creation Time'))

    def __str__(self):
        return f"Email Confirmation for {self.user.username}"

    def create_confirmation(self):
        code = get_random_string(length=6)
        self.code = code
        self.save()
        return code

    def verify_confirmation(self, code):
        if self.user.email_confirmed:
            # Email is already confirmed
            return False

        if self.code == code:
            # Verification successful
            self.user.email_confirmed = True
            self.user.code = None  # Clear the confirmation code
            self.user.save()
            self.delete()  # Remove the confirmation record
            return True

        # Invalid confirmation code
        return False
