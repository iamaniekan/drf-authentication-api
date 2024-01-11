import random
import string

from django.core.mail import send_mail
from django.utils.translation import gettext as _
from django.contrib.auth import login, logout, get_user_model
from django.utils.crypto import get_random_string

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import PermissionDenied

from .models import AccountActivation
from .serializers import (ProfileSerializer, PasswordResetVerifySerializer,
                          EmailChangeSerializer, EmailChangeVerifySerializer,
                          PasswordChangeSerializer, PasswordResetSerializer,
                          ProfileChangeSerializer, LoginSerializer,
                          SignupSerializer, AccountActivationSerializer)

class Account(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileSerializer

    def get(self, request, format=None):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data)

class AccountChange(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileChangeSerializer

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

class Login(APIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            token, created = Token.objects.get_or_create(user=user)

            if user is not None and user.email_confirmed:
                login(request, user)
                response_data = {
                    'user_id': user.id,
                    'success': _('User authenticated.'),
                }
                
                # Include the token in the response header
                response = Response(response_data, status=status.HTTP_200_OK)
                response['Authorization'] = f'Token {token.key}'
                return response
            elif user is not None and not user.email_confirmed:
                return Response({'error': _('Email not confirmed. Please activate your account.')}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error': _('Invalid email or password.')}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Signup(APIView):
    serializer_class = SignupSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            # Check if the email is already registered
            if get_user_model().objects.filter(email=email).exists():
                return Response({'error': _('Email is already registered.')}, status=status.HTTP_400_BAD_REQUEST)

            # Save the user first
            user = serializer.save()
            
            # Create a token for the user
            Token.objects.create(user=user)

            # Create email confirmation
            email_confirmation = AccountActivation(user=user)
            confirmation_code = email_confirmation.create_confirmation()

            # Send the account activation email
            subject = _('Activate Your Account')
            message = f'Your account activation code is: {confirmation_code}'
            from_email = 'Your Email'  
            to_email = [email]

            try:
                # Send the email
                send_mail(subject, message, from_email, to_email, fail_silently=True)
            except Exception as e:
                # Handle email sending failure
                return Response({'error': _('Failed to send activation email.')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'success': _('User signed up successfully.')}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AccountActivationView(APIView):
    serializer_class = AccountActivationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            activation_code = serializer.validated_data.get('code')  

            email_confirmation = AccountActivation.objects.filter(activation_code=activation_code).first()

            if email_confirmation:
                if email_confirmation.verify_confirmation(activation_code):
                    return Response({'success': _('Account Activated. Proceed To Log in')}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': _('Invalid confirmation code.')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': _('Invalid confirmation code.')}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        logout(request)
        return Response({'success': 'User logged out successfully.'}, status=status.HTTP_200_OK)

# Generate a random 6-digit code
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer
    
    def post(self, request, format=None):
        serializer = PasswordResetSerializer(data=request.data)

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
            from_email = 'Your Email'  
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
    serializer_class = PasswordResetVerifySerializer
    
    def post(self, request, format=None):
        serializer = PasswordResetVerifySerializer(data=request.data)

        if serializer.is_valid():
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            # Find the user with the provided verification code
            try:
                user = get_user_model().objects.get(email_verification_code=code)
            except get_user_model().DoesNotExist:
                return Response({'error': _('Invalid verification code.')}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and clear the verification code
            user.set_password(new_password)
            user.email_verification_code = None
            user.save()

            return Response({'success': _('Password reset successfully.')}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeSerializer

    def send_email_change_confirmation(self, user):
        code = get_random_string(length=6)
        user.email_verification_code = code
        user.save()

        subject = 'Confirm Email Change'
        message = f'Your verification code is: {code}'
        from_email = 'Your Email'  
        to_email = user.email

        # Send the email
        send_mail(subject, message, from_email, [to_email], fail_silently=True)

    def post(self, request, format=None):
        serializer = EmailChangeSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            new_email = serializer.validated_data['email']

            # Verify that the provided email matches the logged-in user's email
            if new_email != user.email:
                raise PermissionDenied("Provided email doesn't match the logged-in user's email.")

            # Send the email change confirmation email with code
            self.send_email_change_confirmation(user)

            return Response({'success': 'Email change request sent successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailChangeVerifyView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeVerifySerializer
    
    def post(self, request, format=None):
        serializer = EmailChangeVerifySerializer(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            code = serializer.validated_data['code']
            new_email = serializer.validated_data['new_email']

            # Validate the code and update the email if valid
            if user.email_verification_code == code:
                user.email = new_email
                user.email_verification_code = None  # Clear the verification code
                user.save()
                return Response({'success': 'Email changed successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid or expired verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        serializer = PasswordChangeSerializer(data=request.data)

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
