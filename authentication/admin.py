from django.contrib import admin
from .models import PredictionHistory

class PredictionHistoryAdmin(admin.ModelAdmin):
    list_display = ['url', 'is_phishing', 'username', 'time_stamp']  # Include time_stamp here

admin.site.register(PredictionHistory, PredictionHistoryAdmin)
