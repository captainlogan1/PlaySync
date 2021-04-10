from flask import Flask, render_template
from flask_session import Session
from includes.blueprint import *
import os

SPOTIPY_CLIENT_ID='ae468ff1f96549b28044be8d0419677d'
SPOTIPY_CLIENT_SECRET='c033909b0caf46069a4ee7cbb9169b15'
SPOTIPY_REDIRECT_URI='https://playsync.me/profile'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_TYPE'] = 'filesystem'
#app.config['SESSION_FILE_DIR'] = './.flask_session/'
Session(app)
app.register_blueprint(landing_page)
app.register_blueprint(login_page)
app.register_blueprint(userauth_page)
app.register_blueprint(logout_page)
app.register_blueprint(signup_page)
app.register_blueprint(useradd_page)
app.register_blueprint(about_page)
app.register_blueprint(youtube_operation)
app.register_blueprint(authadd_page)
app.register_blueprint(authget_page)
app.register_blueprint(transfer_page)
app.register_blueprint(profile_page)
app.register_blueprint(youtube_auth)
app.register_blueprint(update_email)
app.register_blueprint(spotify_auth)

# @app.route('/')
# def index():
#     return 'Web App with Python Flask!'

app.run(host='127.0.0.1', port=81)
