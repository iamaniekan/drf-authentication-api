from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from .models import AccountActivation

class AccountTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpassword'
        }
        self.user = get_user_model().objects.create_user(**self.user_data)
        self.client.force_authenticate(user=self.user)

    def test_get_account(self):
        url = reverse('accounts')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_account_info(self):
        url = reverse('edit-details')
        data = {'first_name': 'New', 'last_name': 'Name'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'User information changed.')
        
class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpassword',
            'email_confirmed': True  # Make sure the user is confirmed
        }
        self.user = get_user_model().objects.create_user(**self.user_data)

    def test_login(self):
        url = reverse('login')
        data = {'email': 'test@example.com', 'password': 'testpassword'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Authorization', response.headers)

    def test_invalid_login(self):
        url = reverse('login')
        data = {'email': 'test@example.com', 'password': 'wrongpassword'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) 

class SignupTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_signup(self):
        url = reverse('signup')
        data = {'email': 'newuser@example.com', 'password': 'newuserpassword', 'first_name': 'Sarah', 'last_name': 'Connor'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_duplicate_signup(self):
        url = reverse('signup')
        data = {
            'email': 'test@example.com',
            'password': 'testpassword',
            'first_name': 'John',
            'last_name': 'Doe',
        }
        
        # Create a user with the same email before making the duplicate signup request
        get_user_model().objects.create_user(email='test@example.com', password='existingpassword')

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        
class AccountActivationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'password': 'testpassword'
        }
        self.user = get_user_model().objects.create_user(**self.user_data)
        self.activation_code = '123456'
        self.account_activation = AccountActivation.objects.create(user=self.user, activation_code=self.activation_code)
        self.activation_url = reverse('account-activation')

    def test_account_activation(self):
        activation_data = {'code': self.activation_code}
        response = self.client.post(self.activation_url, activation_data)

        # Refresh the user instance from the database
        self.user.refresh_from_db()

        # Check the response and updated user profile
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertTrue(self.user.email_confirmed)

        # Check that the AccountActivation instance has been deleted
        self.assertFalse(AccountActivation.objects.filter(pk=self.account_activation.pk).exists())

    def test_invalid_activation_code(self):
        activation_data = {'code': 'invalidcode'}
        response = self.client.post(self.activation_url, activation_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid confirmation code.')
