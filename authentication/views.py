from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.shortcuts import redirect,render
import joblib
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
import json
from django.contrib.auth.decorators import login_required
from .forms import PredictionForm
from django.utils import timezone
from .models import PredictionHistory, ReportedURL
import uuid
import json
import requests
import urllib

# You may need to install Requests pip
# python -m pip install requests

class IPQS:
    key = 'YVfcYmF2oEFTThWcudSjhYxy07H1D97i'
    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        url = 'https://www.ipqualityscore.com/api/json/url/%s/%s' % (self.key, urllib.parse.quote_plus(url))
        x = requests.get(url, params = vars)
        print(x.text)
        return (json.loads(x.text))









# Create your views here.

@login_required(login_url='/signin')
def home(request):
    return render(request, 'index.html')
  
def welcome(request):
    return render(request, 'welcomepage.html')
  
def usecases(request):
    return render(request, 'usecases.html')
  
def info(request):
    return render(request, 'info.html')
  
def urlhistory(request):
    return render(request, 'urlhistory.html')

def gethistory(request):
    
        # Fetch link history data for the current user
        link_history = PredictionHistory.objects.filter(username=request.user.username).values('username', 'url', 'time_stamp','is_phishing')
        print
        # Convert QuerySet to list of dictionaries
        link_history_data = list(link_history)
        print(link_history_data)
        # Return the link history data as JSON response
        return JsonResponse(link_history_data, safe=False)
   
        # Return error response if the request method is not POST
        
from django.http import HttpResponseBadRequest

def reporturl(request):
    if request.method == 'POST':
        js = json.loads(request.body.decode('utf-8'))
        url = js.get('url')
        print(url)
        if not url:
            return HttpResponseBadRequest("URL is required")  # Return a 400 Bad Request response if URL is not provided
        
        # Generate a unique ID
        unique_id = uuid.uuid4().hex[:10]  # Generate a 10-character unique ID
        # Insert the URL and other fields into the database
        ReportedURL.objects.create(url=url, username=request.user.username, unique_id=unique_id)
        print("URL reported successfully.")
        # Redirect to the safe browsing report page
        return redirect('https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en')
    else:
        # Handle other HTTP methods if needed
        return HttpResponseNotAllowed(['POST'])

@login_required(login_url='/signin')      
def profile(request):
    # Assuming you have a User model associated with your users
    
    
    # Fetching user-related data
    username = request.user.username
    email = request.user.email
    
    # Counting predicted URLs for the current user
    predicted_urls_count = PredictionHistory.objects.filter(username=username).count()
    
    # Counting reported URLs for the current user
    reported_urls_count = ReportedURL.objects.filter(username=username).count()
    
    # Passing data to the template context
    context = {
        'username': username,
        'email': email,
        'predicted_urls_count': predicted_urls_count,
        'reported_urls_count': reported_urls_count
    }
    print(context)
    
    return render(request, 'profile.html', context)

  


def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('signup')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('signup')
        
        if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('signup')
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('signup')
        
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('signup')
        
        myuser = User.objects.create_user(username, email, pass1)
        # myuser.is_active = False
        
        myuser.save()
        messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
        
        # Welcome Email
        
        return redirect('signin')
        
        
    return render(request, "signup.html")





from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages

def signin(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(username=username, password=password)
        print(user)
        
        if user is not None:
            login(request, user)  # Pass the user object to the login function
            print("User logged in")
            next_url = request.GET.get('next')
            print(next_url)
            if next_url:
                return redirect(next_url)  # Redirect to the URL specified in 'next'
            else:
                return redirect('home')  # Fallback redirection if 'next' is not specified
            
        else:
            messages.error(request, "Invalid username or password")
            print("User not logged in")
            return redirect('signin')
    
    # If the request method is not POST or authentication fails, render the login form again.
    return render(request, "login.html")



def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!!")
    return redirect('signin')





def predict(request):
    if request.method == 'POST':
        # Retrieve the URL from the POST data
        
        js = json.loads(request.body.decode('utf-8'))
        url = js.get('url')
        print("URL:", url) 
        strictness = 0

    #custom feilds
        additional_params = {
        'strictness' : strictness
    }
        ipqs = IPQS()
        result = ipqs.malicious_url_scanner_api(url, additional_params)
        if 'success' in result and result['success'] == True:
          print("Result score : ",result['risk_score'])
          if result['suspicious'] == True or result['malware'] == True or result['phishing'] == True or result['risk_score']>85:
            prediction = 1
          else:
            prediction = 0
        # Load the trained model
        cls = joblib.load('xgboost.sav')
        
        # Initialize a list to store feature values
        lis = []
        
        # Extract features from the URL
        lis.append(havingIP(url))
        lis.append(haveAtSign(url))
        lis.append(getLength(url))
        lis.append(getDepth(url))
        lis.append(redirection(url))
        lis.append(httpDomain(url))
        lis.append(tinyURL(url))
        lis.append(prefixSuffix(url))
        
        # Check if domain information is accessible
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        # Append domain-related features to the list
        lis.append(dns)
        lis.append(1 if dns == 1 else domainAge(domain_name))
        lis.append(1 if dns == 1 else domainEnd(domain_name))
        
        # Extract HTML & JavaScript-based features
        try:
            response = requests.get(url)
        except:
            response = ""
        lis.append(iframe(response))
        lis.append(mouseOver(response))
        lis.append(rightClick(response))
        lis.append(forwarding(response))
        
        print(lis)   # Print the list of feature values
        
        # Make predictions using the trained model
        ans = cls.predict([lis])
        lis.insert(0, getDomain(url))
        print(ans)  # Print the prediction
        print(lis)
        print(prediction)
        data = {
        "success": True,
        "detection": lis,
        "prediction": prediction,
        "risk_score": result['risk_score'],
        "domain_trust": result['domain_trust'],
        "ip_address": result['ip_address'],
        "domain_rank": result['domain_rank'],
        "root_domain": result['root_domain'],
        "category": result['category'],
    }
        print(data)
        
        form = PredictionForm({'url': url, 'is_phishing': prediction, 'username': request.user.username})

        # Validate the form
        if form.is_valid():
            # Save the prediction data to the database
            form.instance.time_stamp = timezone.now()
            form.save()
            print("Prediction data saved successfully.")
        else:
            # If the form is not valid, return an error response
            print("Error saving prediction data.")
        # Return the rendered HTML template
        return JsonResponse(data)
    else:
        # Handle cases where the request method is not POST
        # This block will be executed for GET requests
        return HttpResponse("This view only accepts POST requests")
    
    



#Feature extraction methods
# 1.Domain of the URL (Domain)

def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate
    
# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1
      
      # 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0
  
  # 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1
  
  # 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1