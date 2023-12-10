from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _

from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

class UserProfileSerializer(serializers.ModelSerializer):
    access_token = serializers.SerializerMethodField()
    refresh_token = serializers.SerializerMethodField()

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name', 'access_token', 'refresh_token')

    def get_access_token(self, obj):
        token = RefreshToken.for_user(obj)
        return str(token.access_token)

    def get_refresh_token(self, obj):
        token = RefreshToken.for_user(obj)
        return str(token)
    
class UserProfileChangeSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = get_user_model()
        fields = ('first_name', 'last_name')
        
class UserProfileLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def authenticate(self, **credentials):
        email = credentials.get('email')
        password = credentials.get('password')

        if email and password:
            user = get_user_model().objects.filter(email=email).first()

            if user and user.check_password(password):
                return user
            else:
                raise serializers.ValidationError(_("Invalid email or password."))
        else:
            raise serializers.ValidationError(_("Must include 'email' and 'password'."))
        
class UserProfileSignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})
    
    class Meta:
        model = get_user_model()
        fields = ['first_name', 'last_name', 'email', 'password']
        
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        
        user =get_user_model()(**validated_data)
        
        if password:
            user.set_password(password)
            
        user.save()
        return user
    
class UserPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class UserPasswordResetVerifySerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        code = data.get('code', None)

        if code is None:
            raise serializers.ValidationError({'code': 'Code is required.'})

        return data

class UserEmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()

class UserEmailChangeVerifySerializer(serializers.Serializer):
    code = serializers.CharField()
    new_email = serializers.EmailField()
    
    def validate_code(self, value):
        return value

class UserPasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={'input_type': 'password'})
    new_password = serializers.CharField(style={'input_type': 'password'})

class EmailConfirmationSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)
    