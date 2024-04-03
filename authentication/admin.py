from django.contrib import admin
from .models import PredictionHistory, ReportedURL

class PredictionHistoryAdmin(admin.ModelAdmin):
    list_display = ['url', 'is_phishing', 'username', 'time_stamp']  # Include time_stamp here
class ReportedURLAdmin(admin.ModelAdmin):
    list_display = ['url', 'reported_at', 'username', 'unique_id']  # Include time_stamp here


admin.site.register(PredictionHistory, PredictionHistoryAdmin)
admin.site.register(ReportedURL, ReportedURLAdmin)