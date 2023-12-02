from django.utils.translation import gettext as _
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import UserProfileSerializer, UserProfileChangeSerializer, UserProfileLoginSerializer, UserProfileSignupSerializer

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
