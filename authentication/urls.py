from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
    path('',views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('login', views.login, name='login'),
    path('signout', views.signout, name='signout'),
    path('predict',views.predict, name='predict'),
    path('usecases',views.usecases, name='usecases'),
    path('info',views.info, name='info'),
    path('home1',views.home1, name='home1'),
]
