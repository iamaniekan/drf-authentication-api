# Generated by Django 4.2.7 on 2023-12-15 10:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_revokedtoken'),
    ]

    operations = [
        migrations.DeleteModel(
            name='RevokedToken',
        ),
    ]