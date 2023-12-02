from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.authtoken.models import Token

class UserProfileSerializer(serializers.ModelSerializer):
    token = serializers.SerializerMethodField()
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name', 'token')

    def get_token(self, obj):
        user, created = Token.objects.get_or_create(user=obj)
        return user.key
    
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
    