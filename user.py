from flask_login import UserMixin

import requests, json

USER_URL = "http://ec2-3-87-226-6.compute-1.amazonaws.com/"


class User(UserMixin):
    def __init__(self, id_, first_name, last_name, email, profile_pic):
        self.id = id_
        self.first_name = first_name
        self.last_name = last_name
        self.name = f"{self.first_name} {self.last_name}"
        self.email = email
        self.profile_pic = profile_pic

    @staticmethod
    def parseJSON(json_str):
        obj = json.loads(json_str)
        users = obj.data
        if len(users) <= 0:
            return None
        else:
            user = users[0].data
            return User(
                user.user_id, user.first_name, user.last_name, None, user.picture
            )

    @staticmethod
    def get(user_id):
        response = requests.get(USER_URL + f"?google_id={user_id}")
        if response.status_code == 404:
            return None
        else:
            return User.parseJSON(response.json())

    @staticmethod
    def create(id_, first_name, last_name, email, profile_pic):
        obj = {
            "google_id": id_,
            "first_name": first_name,
            "last_name": last_name,
            "picture": profile_pic,
        }
        requests.post(USER_URL, data=json.dumps(obj))
