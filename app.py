# Python standard libraries
import json
import os
from flask_cors import CORS
# Third party libraries
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

with open("config.json") as json_file:
    config_dict = json.load(json_file)


#ONLY FOR DEVELOPMENT PURPOSES!!!!
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
CORS(app)

from user import User

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

GOOGLE_CLIENT_ID = "1085225843617-9eu61l8q5goe0spdntpap4q6n88btbbf.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"


# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403


# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# @app.route("/profile")
# def profile():
#     def get_profile(uid):
#         return requests.get(user_endpoint+uid).json()

#     return None

@app.route("/items/<item_id>")
def get_items(item_id):
    item_endpoint = config_dict["item_endpoint"]
    return requests.get(item_endpoint+item_id).json()


@app.route("/get_user_cart")
def get_user_cart(user_id, cart_id):
    cart_user_endpoint = config_dict["cart_user_endpoint"]

    return requests.get(cart_user_endpoint).json()

# @app.route("/add_to_cart")
# def add_user_cart(user_id, cart_id, item_id):
#     add_cart_endpoint = config_dict["add_cart_creation"]

#     user_id = 'xxx'
#     cart_id = 'yyy'
#     item_id = 'zzz'# frontend

#     carts = requests.get(url=user_cart_endpoint)
#     if user_id in carts:
#         status_code = add
#     else:
#         create cart
#         status_code = add

#     def add(user_id, cart_id, item_id):
#         post_param = {
#             "user_id": user_id,
#             "cart_id": cart_id,
#             'item_id': item_id
#         }

#         post_req = requests.post(url=cart_creation_endpoint, json=post_param)
#         return post_req.status_code
#     if status_code == '200':
#         return 'success'
#     else:
#         return 'failed'




@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'


@app.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"]
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that we have tokens (yay) let's find and hit URL
    # from Google that gives you user's profile information,
    # including their Google Profile Image and Email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # We want to make sure their email is verified.
    # The user authenticated with Google, authorized our
    # app, and now we've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["name"]

    else:
        return "User email not available or not verified by Google.", 400


    # Create a user in our db with the information provided
    # by Google
    dict1 = users_name.split(' ')
    user = User(
        id_=unique_id, first_name=dict1[0], last_name=dict1[1], email=users_email, profile_pic=picture
    )


    # Doesn't exist? Add to database
    if not User.get(unique_id):
        User.create(unique_id, dict1[0], dict1[1], users_email, picture)


    # Begin user session by logging the user in
    login_user(user)


    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5012, debug=True)