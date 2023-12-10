# Django Rest Framework Authentication API

Django Authentication API is a feature-rich authentication system built with Django and Django Rest Framework. It provides user registration, login, password reset, email change, and other authentication-related functionalities.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [API Endpoints](#api-endpoints)
  - [Authentication](#authentication)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

### Prerequisites

Ensure you have the following prerequisites installed:

- [Python](https://www.python.org/)
- [Django](https://www.djangoproject.com/)
- [Django Rest Framework](https://www.django-rest-framework.org/)
- [djangorestframework-simplejwt](https://github.com/davesque/django-rest-framework-simplejwt)

### Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/django-authentication-api.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd django-authentication-api
    ```

3. **Install the required dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Apply migrations:**

    ```bash
    python manage.py migrate
    ```

5. **Run the development server:**

    ```bash
    python manage.py runserver
    ```

The API should be accessible at `http://localhost:8000/`.

## Usage

### API Endpoints

1. **User Account Information:** `/account/`
    - Method: `GET`
    - Requires authentication

2. **User Account Change:** `/account/change/`
    - Method: `POST`
    - Requires authentication
    - Update user information (first name, last name)

3. **User Login:** `/login/`
    - Method: `POST`
    - Input: Email and password
    - Returns a JWT token on successful login

4. **User Signup:** `/signup/`
    - Method: `POST`
    - Input: First name, last name, email, and password
    - Returns a JWT token on successful signup

5. **User Logout:** `/logout/`
    - Method: `POST`
    - Requires authentication
    - Logs out the user

6. **Password Reset Request:** `/password-reset/`
    - Method: `POST`
    - Input: Email
    - Sends a verification code for password reset to the user's email

7. **Password Reset Verify:** `/password-reset/verify/`
    - Method: `POST`
    - Input: Verification code and new password
    - Resets the user's password

8. **Email Change Request:** `/email-change/`
    - Method: `POST`
    - Requires authentication
    - Sends a verification code for email change to the user's email

9. **Email Change Verify:** `/email-change/verify/`
    - Method: `POST`
    - Input: Verification code and new email
    - Changes the user's email

10. **Password Change:** `/password-change/`
    - Method: `POST`
    - Requires authentication
    - Input: Old password and new password
    - Changes the user's password

### Authentication

- JWT (JSON Web Token) authentication is used for most endpoints.

## Configuration

Update the `settings.py` file for Django and Django Rest Framework configurations. Refer to the documentation of [django-oauth-toolkit](https://django-oauth-toolkit.readthedocs.io/en/latest/) and [djangorestframework-simplejwt](https://github.com/davesque/django-rest-framework-simplejwt) for advanced configuration options.

## Contributing

- Fork the repository.
- Create a new branch for your feature: git checkout -b feature-name.
- Commit your changes: git commit -m 'Add new feature'.
- Push to the branch: git push origin feature-name.
- Submit a pull request.


 
