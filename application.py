# Python standard libraries
import functools
import json
import os
from flask_cors import CORS

# Third party libraries
from flask import Flask, redirect, Response, request, url_for, render_template
from flask_login import (
    LoginManager,
    current_user,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749 import endpoints
import requests
from middleware import login_required
from user import User

import numpy as np

with open("config.json") as json_file:
    config_dict = json.load(json_file)

# ONLY FOR DEVELOPMENT PURPOSES!!!!
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Configuration
# GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
# GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)

GOOGLE_CLIENT_ID = (
    "1085225843617-9eu61l8q5goe0spdntpap4q6n88btbbf.apps.googleusercontent.com"
)
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Flask app setup
application = Flask(__name__)
application.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(application)


@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403


# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def microservice_endpoint(name, user_id, appendix=""):
    return config_dict[f"{name}_endpoint"] + "/" + str(user_id) + appendix


def get_from_microservice(microservice_name, user_id, appendix=""):
    endpoint = microservice_endpoint(microservice_name, user_id, appendix)
    print(appendix, user_id, endpoint)
    return requests.get(endpoint).json()


def get_user(user_id):
    return get_from_microservice("user", user_id)


def get_contact(user_id):
    return (
        get_from_microservice("contact", user_id, "/email")
        | get_from_microservice("contact", user_id, "/phone")
        | get_from_microservice("contact", user_id, "/address")
    )


@application.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = current_user.get_id()
    ##DEBUG USE
    print("Hello")
    if request.method == "GET":

        user_obj = get_user(user_id)
        contact_obj = get_contact(user_id)
        user_obj["data"] |= contact_obj

        context = dict(user_obj=user_obj)
        return render_template("profile.html", **context)

    elif request.method == "POST":
        print(request.json)


def update_profile(url, update_item, change):
    url = url + "/" + update_item
    post_param = {
        update_item: change,
    }
    if_exists = requests.get(url).content
    if if_exists != b"Not found":
        post_req = requests.put(url=url, json=post_param)
    else:
        post_req = requests.post(url=url, json=post_param)

    status_code = post_req.status_code

    return status_code


@application.route("/profile/update_email")
@login_required
def update_email():
    user_id = current_user.get_id()
    email = request.args.get("email")
    _endpoint = config_dict["contact_endpoint"] + "/" + str(user_id)
    status_code = update_profile(_endpoint, "email", email)
    if status_code == 200:
        return "success"
    else:
        return "failed"


@application.route("/profile/update_address")
@login_required
def update_address():
    user_id = current_user.get_id()
    address = request.args.get("address")
    _endpoint = config_dict["contact_endpoint"] + "/" + str(user_id)
    status_code = update_profile(_endpoint, "address", address)
    if status_code == 200:
        return "success"
    else:
        return "failed"


@application.route("/profile/update_phone")
@login_required
def update_phone():
    user_id = current_user.get_id()
    phone = request.args.get("phone")
    _endpoint = config_dict["contact_endpoint"] + "/" + str(user_id)
    status_code = update_profile(_endpoint, "phone", phone)
    if status_code == 200:
        return "success"
    else:
        return "failed"


@application.route("/shopping/<cart_id>")
@login_required
def get_items_all(cart_id):
    offset = request.args.get("offset")
    limit = request.args.get("limit")
    all_item_endpoint = config_dict["item_endpoint"]

    if offset is not None:
        all_item_endpoint += f"?offset={offset}"
    if limit is not None:
        all_item_endpoint += f"&limit={limit}"
    req = requests.get(all_item_endpoint).json()

    for i, item in enumerate(req["data"]):
        item_id = item["item_id"]

        item["add"] = f"<a href='/add_to_cart/{cart_id}/{item_id}'>add_to_cart</a>"
        req["data"][i] = item
    html = '<a class="button" href="/get_items_in_cart/{}">Current Cart</a>'.format(
        cart_id
    )
    headers = (
        "<tr>" + "".join([f"<th>{val}</th>" for val in req["data"][0].keys()]) + "</tr>"
    )
    thead = f"<thead>{headers}</thead>"
    tbody = [
        "<tr>" + "".join([f"<td>{val}</td>" for val in row.values()]) + "</tr>"
        for row in req["data"]
    ]
    tbody = "\n".join(tbody)
    tbody = f"<tbody>{tbody}</tbody>"
    html += f"<table border=1>{thead}{tbody}</table>"

    prev, next = req["link"][0]["href"], req["link"][-1]["href"]
    html += f'<a href="{prev}">previous</a> &nbsp'
    html += f'<a href="{next}">next</a>'
    return html


@application.route("/create_cart")
@login_required
def create_cart():
    user_id = current_user.get_id()
    _endpoint = config_dict["cart_endpoint"]
    generated_cart_id = int(round(np.random.random(), 5) * 10000)
    res = requests.post(
        _endpoint, json={"user_id": user_id, "cart_id": generated_cart_id}
    )
    while res.status_code != 200:
        generated_cart_id = int(round(np.random.random(), 5) * 10000)
        res = requests.post(
            _endpoint, json={"user_id": user_id, "cart_id": generated_cart_id}
        )
    html = "<a href = '/shopping/{}'>continue shopping</a>".format(generated_cart_id)
    # return {"user_id":user_id,"cart_id":generated_cart_id}
    return html


@application.route("/get_carts")
@login_required
def get_user_cart():
    user_id = current_user.get_id()
    _endpoint = config_dict["cart_endpoint"] + "/users/{}".format(user_id)
    res = requests.get(_endpoint)

    if res.status_code == 200:
        cart_ls = [x.get("cart_id") for x in res.json()]
        data = {"status_code": res.status_code, "cart_ls": cart_ls}
        context = dict(data=data)

    return render_template("carts.html", **context)


@application.route("/delete_cart/<cart_id>")
@login_required
def delete_cart(cart_id):
    user_id = current_user.get_id()
    _endpoint = config_dict["cart_endpoint"]
    res = requests.delete(_endpoint, json={"cart_id": cart_id, "user_id": user_id})
    if res.status_code == 200:
        return "Successfully Deleted Cart"
    else:
        return "Failed to Delete Cart"


@application.route("/delete_items_in_cart/<cart_id>/<item_id>")
@login_required
def delete_items_in_cart(cart_id, item_id):
    _endpoint = config_dict["cart_endpoint"] + "/" + str(cart_id)
    res = requests.delete(_endpoint, json={"item_id": item_id})
    if res.status_code == 200:
        return "Successfully Deleted Item"
    else:
        return "Failed to Delete Item"


@application.route("/change_item_count_in_cart/<cart_id>/<item_id>")
@login_required
def change_item_count_in_cart(cart_id, item_id):
    new_count = request.args.get("changeItem")

    res = requests.put(
        config_dict["cart_endpoint"] + "/{}".format(cart_id),
        json={"item_id": item_id, "count": new_count},
    )
    if res.status_code == 200:
        html = "Successfully Updated Item Count"
    else:
        html = "Failed to Update Count"
    html += "<br><br>"
    html += '<a class="button" href="/shopping/{}">Continue Shopping</a>'.format(
        cart_id
    )
    html += "<br><br>"
    html += '<a class="button" href="/get_items_in_cart/{}">My Current Cart</a>'.format(
        cart_id
    )
    return html


@application.route("/get_items_in_cart/<cart_id>")
@login_required
def get_items_in_cart(cart_id):
    _endpoint = config_dict["cart_endpoint"] + "/{}/items".format(cart_id)
    res = requests.get(_endpoint)
    if res.status_code == 200:
        html = ""
        # return json2html.convert(res.json())
        req = res.json()
        # return str(req)
        for i, item in enumerate(req):
            item_id = item["item_id"]
            item[
                "change count"
            ] = f"""
            <form action="/change_item_count_in_cart/{cart_id}/{item_id}">
                <label for="changeItem"></label>
                <input type="text", size="1",id="changeItem-{cart_id}-{item_id}" name="changeItem">
            <input type="submit" value="Update">
            </form> 
            """
            item[
                "remove"
            ] = f"<a href='/delete_items_in_cart/{cart_id}/{item_id}'>Remove</a>"
            req[i] = item
        headers = (
            "<tr>" + "".join([f"<th>{val}</th>" for val in req[0].keys()]) + "</tr>"
        )
        thead = f"<thead>{headers}</thead>"
        tbody = [
            "<tr>" + "".join([f"<td>{val}</td>" for val in row.values()]) + "</tr>"
            for row in req
        ]
        tbody = "\n".join(tbody)
        tbody = f"<tbody>{tbody}</tbody>"
        html += f"<table border=1>{thead}{tbody}</table>"
        html += f"<a href='/checkout/{cart_id}'>Checkout</a>"
        return html
    else:
        return {}


@application.route("/checkout/<cart_id>")
@login_required
def checkout(cart_id):
    # user_id =
    html = "Congrats! Your order is sumbitted."
    html += "<br><br>"
    html += '<a href="/">Return to Home</a>'
    # html += "<br><br>"
    # html += '<a class="button" href="/get_user_cart/{}">Start Shopping</a>'.format(current_user.id)
    return html


@application.route("/add_to_cart/<cart_id>/<item_id>")
@login_required
def add_to_cart(cart_id, item_id):
    _endpoint = config_dict["cart_endpoint"] + "/{}/items".format(cart_id)
    res = requests.get(_endpoint)
    if res.status_code == 200:
        item_ls = [x["item_id"] for x in res.json()]
        if item_id in item_ls:
            current_count = res.json()[item_ls.index(item_id)]["count"]
            requests.put(
                config_dict["cart_endpoint"] + "/{}".format(cart_id),
                json={"item_id": item_id, "count": current_count + 1},
            )
        else:
            requests.post(
                config_dict["cart_endpoint"] + "/{}".format(cart_id),
                json={"item_id": item_id, "count": 1},
            )
    else:
        requests.post(
            config_dict["cart_endpoint"] + "/{}".format(cart_id),
            json={"item_id": item_id, "count": 1},
        )
    html = "Successfully Added <br><br><br>"
    html += '<a class="button" href="/shopping/{}">Continue Shopping</a>'.format(
        cart_id
    )
    html += "<br><br>"
    html += '<a class="button" href="/get_items_in_cart/{}">My Current Cart</a>'.format(
        cart_id
    )

    return html


@application.route("/")
def index():
    if current_user.is_authenticated:
        data = {'is_authenticated': current_user.is_authenticated, 'username': current_user.name,
                'profile_pic': current_user.profile_pic, 'user_id': current_user.id}

    else:
        data = {'is_authenticated': current_user.is_authenticated}

    context = dict(data=data)
    return render_template("index.html", **context)


@application.route("/login")
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
        scope=["openid", "email", "profile"],
    )

    return redirect(request_uri)


@application.route("/login/callback")
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
    dict1 = users_name.split(" ")
    user = User(
        id_=unique_id,
        first_name=dict1[0],
        last_name=dict1[1],
        email=users_email,
        profile_pic=picture,
    )

    # Doesn't exist? Add to database
    if not User.get(unique_id):
        User.create(unique_id, dict1[0], dict1[1], users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for("index"))


@application.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == "__main__":
    application.run(host="127.0.0.1", port=5012)