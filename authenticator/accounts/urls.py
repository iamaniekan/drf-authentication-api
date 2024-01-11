from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . import views


urlpatterns = [
    path('', views.Account.as_view(), name = 'accounts'),
    path('edit-details/', views.AccountChange.as_view(), name='edit-details'),
    path('login/', views.Login.as_view(),name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('signup/', views.Signup.as_view(), name='signup'),
    path('activate-account/', views.AccountActivationView.as_view(), name='account-activation'),
    path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('email-change/', views.EmailChangeView.as_view(), name='email-change'),
    path('email-change/verify/', views.EmailChangeVerifyView.as_view(), name='email-change-verify'),
]

urlpatterns = format_suffix_patterns(urlpatterns)