
from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
   #import the views from the authentication app
    path('', include('authentication.urls')),
    
    
]
