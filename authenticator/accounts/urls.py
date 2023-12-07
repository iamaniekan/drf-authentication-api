from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . import views


urlpatterns = [
    path('', views.UserAccount.as_view()),
    path('edit-details/', views.UserAccountChange.as_view(), name='edit-details'),
    path('login/', views.UserLogin.as_view(),name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('signup/', views.UserSignup.as_view(), name='signup'),
    path('password-change/', views.UserPasswordChangeView.as_view(), name='password-change'),
    path('password-reset/', views.UserPasswordResetView.as_view(), name='password-reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('email-change/', views.UserEmailChangeView.as_view(), name='email-change'),
    path('email-change/verify/', views.UserEmailChangeVerifyView.as_view(), name='email-change-verify'),
]

urlpatterns = format_suffix_patterns(urlpatterns)