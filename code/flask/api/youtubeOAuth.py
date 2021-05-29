import os
import flask
from flask import request
import requests
import pickle
import sys
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

CLIENT_SECRETS_FILE = "api/client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/youtube"]
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

caches_folder = '/tmp/youtube_caches/'
if not os.path.exists(caches_folder):
    os.makedirs(caches_folder)
    
def authorize_yt():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = 'https://playsync.me/ytcallback'
    authorization_url, state = flow.authorization_url(
      # This parameter enables offline access which gives your application
      # both an access and refresh token.
      access_type='offline',
      # This parameter enables incremental auth.
      include_granted_scopes='false'
    )
    # Store the state in the session so that the callback can verify that
    # the authorization server response.
    flask.session['state'] = state
    return flask.redirect(authorization_url)

def oauth2callback(user):
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = 'https://playsync.me/ytcallback'
    authorization_response = flask.request.url
    # Google API keeps redirecting to localhost, I think this is a NGINX issue. Temporary .replace() fix.
    authorization_response = authorization_response.replace('http://127.0.0.1:81', 'https://playsync.me')
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)
    credentials = credentials_to_dict(credentials)
    # Pickling user oAuth credentials until I can find a better way worth doing. 
    pickle.dump( credentials, open( caches_folder + user, "wb" ) )  
    return flask.redirect('/profile')

#Grabs the username for the connected youtube account if possible
def get_name():
    user = request.cookies.get('user').split(':')[1]
    try:
        oAuthCreds = pickle.load( open( caches_folder + user, "rb" ) )
    except:
        pass
    try:
        credentials = google.oauth2.credentials.Credentials(
                oAuthCreds['token'],
                refresh_token = oAuthCreds["refresh_token"],
                token_uri = oAuthCreds["token_uri"],
                client_id = oAuthCreds["client_id"],
                client_secret = oAuthCreds["client_secret"],
                scopes = oAuthCreds["scopes"])
        flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES)
        youtube = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)
        yt_request = youtube.channels().list(
            part="snippet,contentDetails,statistics",
            mine=True
        )
    except:
        pass
    ytUser = 'Not Connected'
    try: 
        response = yt_request.execute()
        ytUser = response['items'][0]['snippet']['localized']['title']
    except:
        pass
    return ytUser

def sign_out(user):
    # Grab user oAuth credentials and send a post request to google to revoke access.
    user = request.cookies.get('user').split(':')[1]
    try:
        oAuthCreds = pickle.load( open( caches_folder + user, "rb" ) )
    except:
        return flask.redirect('./profile')
    token = oAuthCreds['token']
    requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    # Access removed through google we can now cleanup the local storage.
    try:
        os.remove(caches_folder + user)
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
    return flask.redirect('/profile')

def ytotest2(user):
    try:
        oAuthCreds = pickle.load( open( caches_folder + user, "rb" ) )
    except:
        return flask.redirect('ytoauth')
    credentials = google.oauth2.credentials.Credentials(
            oAuthCreds['token'],
            refresh_token = oAuthCreds["refresh_token"],
            token_uri = oAuthCreds["token_uri"],
            client_id = oAuthCreds["client_id"],
            client_secret = oAuthCreds["client_secret"],
            scopes = oAuthCreds["scopes"])
    flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, SCOPES)
    youtube = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)
    request = youtube.playlists().list(
        part="snippet,contentDetails",
        maxResults=25,
        mine=True,)
    try:
        response = request.execute()
        playlistNum = response['pageInfo']['totalResults']
        playlists = []
        for i in range(playlistNum):
            playlists.append({'id': response['items'][i]['id'],
                'title': response['items'][i]['snippet']['title'],
                'thumbnail': response['items'][i]['snippet']['thumbnails']['default']['url']})
        print(playlists, file=sys.stderr)
        return flask.jsonify(playlists)
    except:
        print('Possible refresh error check that PlaySync is authorized for Youtube', file=sys.stderr)
        return flask.redirect('ytoauth')

def credentials_to_dict(credentials):
    return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


