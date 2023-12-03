from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . import views


urlpatterns = [
    path('', views.UserAccount.as_view()),
    path('change/', views.UserAccountChange.as_view()),
    path('login/', views.UserLogin.as_view()),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('signup/', views.UserSignup.as_view()),
    path('password-reset/', views.UserPasswordResetView.as_view(), name='password-reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('email-change/', views.UserEmailChangeView.as_view(), name='email-change'),
    path('email-change/verify/', views.UserEmailChangeVerifyView.as_view(), name='email-change-verify'),
    path('password-change/', views.UserPasswordChangeView.as_view(), name='password-change'),
]

urlpatterns = format_suffix_patterns(urlpatterns)