# Use the official Python image
FROM python:3.11.5

# Set the working directory
WORKDIR /app

# Create and activate the virtual environment
RUN python -m venv .env
RUN /bin/bash -c "source .env/bin/activate"

# Copy only the requirements file into the container
COPY requirements.txt /app/

# Upgrade pip and install dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy the application code into the container
COPY . /app

# Run migrations and start the application
CMD ["bash", "-c", "python manage.py makemigrations && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
