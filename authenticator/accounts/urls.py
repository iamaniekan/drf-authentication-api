from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . import views


urlpatterns = [
    path('', views.UserAccount.as_view()),
    path('change/', views.UserAccountChange.as_view()),
    path('login/', views.UserLogin.as_view()),
    path('signup/', views.UserSignup.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)