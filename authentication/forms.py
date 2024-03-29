from django import forms
from .models import PredictionHistory

class PredictionForm(forms.ModelForm):
    class Meta:
        model = PredictionHistory
        fields = ['url', 'is_phishing', 'username']
