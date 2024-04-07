from django.contrib import admin
from django.urls import path, include
from . import views


urlpatterns = [
    path('',views.welcome, name='welcome'),
    path('home',views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('signin', views.signin, name='signin'),
    path('signout', views.signout, name='signout'),
    path('predict',views.predict, name='predict'),
    path('usecases',views.usecases, name='usecases'),
    path('info',views.info, name='info'),
    path('welcome',views.welcome, name='welcome'),
    path('urlhistory',views.urlhistory, name='urlhistory'),
    path('gethistory',views.gethistory, name='gethistory'),
    path('reporturl', views.reporturl, name='reporturl'),
    path('profile', views.profile, name='profile'),
    
]
