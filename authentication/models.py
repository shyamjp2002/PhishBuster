from django.db import models
from django.contrib.auth.models import User

class PredictionHistory(models.Model):
    id = models.AutoField(primary_key=True)  # Unique ID field
    url = models.URLField()
    is_phishing = models.BooleanField()
    username = models.CharField(max_length=150)  # Store username as a string
    time_stamp = models.DateTimeField(auto_now_add=True)

