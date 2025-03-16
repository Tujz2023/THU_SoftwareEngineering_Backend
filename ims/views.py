import json
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from ims.models import User
# from ims.models import Conversation, User, Message, Request, Invitation
from utils.utils_request import BAD_METHOD, request_failed, request_success, return_field
from utils.utils_require import MAX_CHAR_LENGTH, CheckRequire, require
from utils.utils_time import get_timestamp
from utils.utils_jwt import generate_jwt_token, check_jwt_token

@CheckRequire
def login(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))
    
    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    import re
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return request_failed(1, "Invalid email", 400)
    password = require(body, "password", "string", err_msg="Missing or error type of [password]")
    
    user = User.objects.filter(email=email).first()
    if user is None:
        return request_failed(1, "User not found", 400)
    elif user.password != password:
        return request_failed(2, "Wrong password", 401)
    # checking success or new user
    return_data = {
            "token": generate_jwt_token(email)
        }
    return request_success(return_data)
