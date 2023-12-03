from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.utils.translation import gettext as _
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView

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

class UserLogin(APIView):
    serializer_class = UserProfileLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request, user)
                token, created = Token.objects.get_or_create(user=user)
                response_data = {
                    'user_id': user.id,
                    'success': _('User authenticated.')
                }
                response = Response(response_data, status=status.HTTP_200_OK)
                response['Authorization'] = 'Token {}'.format(token.key)
                return response
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
                return Response({'error': _('Email is already registered.')},
                                status=status.HTTP_400_BAD_REQUEST)

            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)

            return Response({'success': _('User signed up successfully.'),
                             'token': token.key},
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogoutView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        logout(request)
        return Response({'success': 'User logged out successfully.'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    def post(self, request, format=None):
        serializer = UserPasswordResetSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Find the user with the provided email
            try:
                user = get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                return Response({'error': _('User with this email does not exist.')}, status=status.HTTP_400_BAD_REQUEST)

            # Generate a unique code for password reset
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Construct the reset link with the code
            reset_link = f'http://yourwebsite.com/reset-password/verify/?uid={uid}&token={token}'

            # Send the reset password email
            subject = _('Reset Your Password')
            message = f'Click the following link to reset your password: {reset_link}'
            from_email = 'your-email@example.com'  # Update with your email
            to_email = [email]

class PasswordResetVerifyView(APIView):
    def post(self, request, format=None):
        serializer = UserPasswordResetVerifySerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            # Decode the user ID from the code
            try:
                uid = force_str(urlsafe_base64_decode(code))
                user = get_user_model().objects.get(pk=uid, email=email)
            except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
                return Response({'error': _('Invalid verification code.')}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the verification code is valid
            if not default_token_generator.check_token(user, code):
                return Response({'error': _('Invalid verification code.')}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            return Response({'success': _('Password reset successfully.')}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserEmailChangeView(APIView):
    permission_classes = (IsAuthenticated,)

    def send_email_change_confirmation(self, user, confirmation):
        subject = 'Confirm Email Change'
        from_email = 'your_email@example.com'  # Replace with your email
        to_email = user.email
        
        # Construct the confirmation link with the code
        confirmation_link = reverse('email-change-verify')
        confirmation_link += f'?code={confirmation.code}'

        # Render the email template
        email_context = {'user': user, 'confirmation_code': confirmation.code}
        html_message = render_to_string('email_change_template.html', email_context)
        plain_message = strip_tags(html_message)

        # Send the email
        send_mail(subject, plain_message, from_email, [to_email], html_message=html_message)

    def post(self, request, format=None):
        serializer = UserEmailChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            new_email = serializer.validated_data['email']

            # Generate code for email change
            confirmation = EmailConfirmation.create(user)

            # Send the email change confirmation email
            self.send_email_change_confirmation(user, confirmation)

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


class UserPasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        serializer = UserPasswordChangeSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            current_password = serializer.validated_data['current_password']
            new_password = serializer.validated_data['new_password']

            # Check if the current password is correct
            if not user.check_password(current_password):
                return Response({'error': _('Current password is incorrect.')}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            # Optional: Invalidate existing authentication tokens if needed

            return Response({'success': 'Password changed successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailConfirmationView(APIView):
    serializer_class = EmailConfirmationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            code = serializer.validated_data['code']

            email_confirmation = EmailConfirmation.objects.filter(code=code).first()

            if email_confirmation:
                email_confirmation.user.email_confirmed = True
                email_confirmation.user.save()
                email_confirmation.delete()

                return Response({'success': _('Email confirmed successfully.')}, status=status.HTTP_200_OK)

            return Response({'error': _('Invalid confirmation code.')}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)