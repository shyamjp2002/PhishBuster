from django.db import models
from django.contrib.auth.models import User

class PredictionHistory(models.Model):
    id = models.AutoField(primary_key=True)  # Unique ID field
    url = models.URLField()
    is_phishing = models.BooleanField()
    username = models.CharField(max_length=150)  # Store username as a string
    time_stamp = models.DateTimeField(auto_now_add=True)


class ReportedURL(models.Model):
    url = models.URLField(max_length=200)
    reported_at = models.DateTimeField(auto_now_add=True)
    username = models.CharField(max_length=100)
    unique_id = models.CharField(max_length=50, unique=True)