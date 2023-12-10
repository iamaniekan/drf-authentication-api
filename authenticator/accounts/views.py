import random
import string

from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import gettext as _
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.utils.crypto import get_random_string
from django.utils import timezone


from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication  
from rest_framework_simplejwt.tokens import RefreshToken



from .models import EmailConfirmation

from .serializers import (UserProfileSerializer,UserPasswordResetVerifySerializer,
                          UserEmailChangeSerializer,UserEmailChangeVerifySerializer,
                          UserPasswordChangeSerializer,UserPasswordResetSerializer,
                          UserProfileChangeSerializer,UserProfileLoginSerializer,
                          UserPasswordResetSerializer, UserProfileChangeSerializer, 
                          UserProfileSignupSerializer, EmailConfirmationSerializer)

class UserAccount(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserProfileSerializer

    def get(self, request, format=None):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data)

class UserAccountChange(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserProfileChangeSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = request.user

            if 'first_name' in serializer.validated_data:
                user.first_name = serializer.validated_data['first_name']
            if 'last_name' in serializer.validated_data:
                user.last_name = serializer.validated_data['last_name']

            user.save()

            content = {'success': _('User information changed.')}
            return Response(content, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogin(TokenObtainPairView):
    serializer_class = UserProfileLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            user = authenticate(request, email=email, password=password)

            if user is not None and user.email_confirmed:
                login(request, user)
                response_data = {
                    'user_id': user.id,
                    'success': _('User authenticated.'),
                }
                return Response(response_data, status=status.HTTP_200_OK)
            elif user is not None and not user.email_confirmed:
                return Response({'error': _('Email not confirmed. Please activate your account.')}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error': _('Invalid email or password.')}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

  
    
class UserSignup(APIView):
    serializer_class = UserProfileSignupSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            # Check if the email is already registered
            if get_user_model().objects.filter(email=email).exists():
                return Response({'error': _('Email is already registered.')}, status=status.HTTP_400_BAD_REQUEST)

            # Save the user first
            user = serializer.save()

            # Create email confirmation
            email_confirmation = EmailConfirmation(user=user)
            confirmation_code = email_confirmation.create_confirmation()

            # Send the account activation email
            subject = _('Activate Your Account')
            message = f'Your account activation code is: {confirmation_code}'
            from_email = 'itsaniekan@gmail.com'  
            to_email = [email]

            try:
                # Send the email
                send_mail(subject, message, from_email, to_email, fail_silently=True)
            except Exception as e:
                # Handle email sending failure
                return Response({'error': _('Failed to send activation email.')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({'success': _('User signed up successfully.')}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class EmailConfirmationView(APIView):
    serializer_class = EmailConfirmationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            code = serializer.validated_data['code']

            email_confirmation = EmailConfirmation.objects.filter(code=code).first()

            if email_confirmation:
                if email_confirmation.verify_confirmation(code):
                    return Response({'success': _('Account Activated. Proceed To Log in')}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': _('Invalid confirmation code.')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': _('Invalid confirmation code.')}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogoutView(APIView):
    authentication_classes = (IsAuthenticated,)
    permission_classes = (JWTAuthentication,)

    def post(self, request, format=None):
        logout(request)
        return Response({'success': 'User logged out successfully.'}, status=status.HTTP_200_OK)

# Generate a random 6-digit code
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

class UserPasswordResetView(APIView):
    def post(self, request, format=None):
        serializer = UserPasswordResetSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                # Find the user with the provided email
                user = get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                return Response({'error': _('User with this email does not exist.')}, status=status.HTTP_400_BAD_REQUEST)

            # Generate a unique code for password reset
            code = generate_verification_code()

            # Attach the code to the user
            user.email_verification_code = code
            user.save()

            # Send the reset password email
            subject = _('Reset Your Password')
            message = f'Your verification code is: {code}'
            from_email = 'itsaniekan@gmail.com'  
            to_email = [email]

            try:
                # Send the email
                send_mail(subject, message, from_email, to_email, fail_silently=True)
            except Exception as e:
                # Handle email sending failure
                return Response({'error': _('Failed to send reset email.')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'success': _('Verification code sent successfully.')}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetVerifyView(APIView):
    def post(self, request, format=None):
        serializer = UserPasswordResetVerifySerializer(data=request.data)

        if serializer.is_valid():
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            if request.user.is_authenticated:
                user = request.user

                if user.email_verification_code != code:
                    return Response({'error': _('Invalid verification code.')}, status=status.HTTP_400_BAD_REQUEST)

                user.set_password(new_password)
                user.email_verification_code = None  # Clear the verification code after use
                user.save()

                return Response({'success': _('Password reset successfully.')}, status=status.HTTP_200_OK)
            else:
                return Response({'error': _('User is not authenticated.')}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserEmailChangeView(APIView):
    permission_classes = (IsAuthenticated,)

    def send_email_change_confirmation(self, user, confirmation):
        subject = 'Confirm Email Change'
        message = f'Your verification code is: {confirmation.code}'
        from_email = 'itsaniekan@gmail.com'  
        to_email = user.email
        
        # Send the email
        send_mail(subject, message, from_email, [to_email], fail_silently=True)
        
    
    def post(self, request, format=None):
        serializer = UserEmailChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            new_email = serializer.validated_data['email']

            # Use get_or_create to simplify the code
            existing_confirmation, created = EmailConfirmation.objects.get_or_create(
                user=user,
                defaults={'code': get_random_string(length=6), 'created_at': timezone.now()}
            )

            # If the object was not created, update the code and timestamp
            if not created:
                existing_confirmation.code = get_random_string(length=6)
                existing_confirmation.created_at = timezone.now()
                existing_confirmation.save()

            # Send the email change confirmation email with code
            self.send_email_change_confirmation(user, existing_confirmation)

            return Response({'success': 'Email change request sent successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserEmailChangeVerifyView(APIView):
    def post(self, request, format=None):
        serializer = UserEmailChangeVerifySerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            code = serializer.validated_data['code']
            new_email = serializer.validated_data['new_email']

            # Validate the code and update the email if valid
            if EmailConfirmation.verify(user, code):
                user.email = new_email
                user.save()
                return Response({'success': 'Email changed successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid or expired verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordChangeView(TokenObtainPairView):
    permission_classes = (JWTAuthentication,)

    def post(self, request, format=None):
        serializer = UserPasswordChangeSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']

            # Check if the current password is correct
            if not user.check_password(old_password):
                return Response({'error': _('Current password is incorrect.')}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            # Optional: Invalidate existing authentication tokens if needed

            return Response({'success': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
