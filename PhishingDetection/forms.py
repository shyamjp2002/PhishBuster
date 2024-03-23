from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from django.contrib.auth.models import User

from django import forms

from django.forms.widgets import PasswordInput, TextInput

#Register user form
class CreateUserForm(UserCreationForm):
    class Meta:
        
        model = User
        fields = ['username', 'password1',]
        
        
#Authenticate user form
class LoginForm(AuthenticationForm):
    
    username = forms.CharField(widget=TextInput())
    password = forms.CharField(widget=PasswordInput())
