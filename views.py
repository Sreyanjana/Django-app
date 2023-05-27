import os
import json
import urllib.parse

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.urls import reverse
from django.conf import settings
from django.views import View

from google.auth.transport import requests
from google.oauth2 import id_token

class GoogleCalendarInitView(View):
    def get(self, request):
        # Step 1: Prompt user for Google credentials
        auth_url, state = self.get_auth_url_and_state()
        request.session['oauth_state'] = state
        return HttpResponseRedirect(auth_url)

    def get_auth_url_and_state(self):
        redirect_uri = request.build_absolute_uri(reverse('google_calendar_redirect'))
        state = os.urandom(16).hex()
        params = {
            'client_id': settings.CLIENT_ID,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'https://www.googleapis.com/auth/calendar.readonly',
            'state': state,
        }
        auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode(params)
        return auth_url, state

class GoogleCalendarRedirectView(View):
    def get(self, request):
        # Step 2: Handle redirect request and retrieve access token
        code = request.GET.get('code')
        state = request.GET.get('state')

        if state != request.session.get('oauth_state'):
            return HttpResponseBadRequest('Invalid state parameter')

        redirect_uri = request.build_absolute_uri(reverse('google_calendar_redirect'))
        token = self.get_access_token(code, redirect_uri)
        if 'error' in token:
            return HttpResponseBadRequest(f"Error: {token['error']}")

        # Step 3: Use access token to get list of events
        events = self.get_calendar_events(token['access_token'])
        return JsonResponse(events)

    def get_access_token(self, code, redirect_uri):
        params = {
            'code': code,
            'client_id': settings.CLIENT_ID,
            'client_secret': settings.CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }
        token_url = 'https://accounts.google.com/o/oauth2/token'
        response = requests.post(token_url, data=params)
        token = json.loads(response.text)
        return token

    def get_calendar_events(self, access_token):
        events_url = 'https://www.googleapis.com/calendar/v3/events'
        headers = {
            'Authorization': f'Bearer {access_token}',
        }
        response = requests.get(events_url, headers=headers)
        events = json.loads(response.text)
        return events