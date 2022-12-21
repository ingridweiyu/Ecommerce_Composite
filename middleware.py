import functools
from flask import redirect, request, url_for
from flask_login import (
    current_user
)

def login_required(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)

    return secure_function
