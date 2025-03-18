import json
from django.http import HttpRequest, HttpResponse
from django.db.models import Q
from django.shortcuts import render

from ims.models import User
from ims.models import Conversation, User, Message, Request, Invitation
from utils.utils_request import BAD_METHOD, request_failed, request_success, return_field
from utils.utils_require import MAX_CHAR_LENGTH, CheckRequire, require
from utils.utils_time import get_timestamp
from utils.utils_jwt import generate_jwt_token, check_jwt_token
import re

@CheckRequire
def login(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))
    
    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return request_failed(1, "Invalid email", 400)
    password = require(body, "password", "string", err_msg="Missing or error type of [password]")
    user = User.objects.filter(email=email).first()
    if user is None:
        return request_failed(-1, "User not found", 404)
    elif user.deleted:
        return request_failed(1, "User deleted", 404)
    elif user.password != password:
        return request_failed(-3, "Wrong password", 401)
    # checking success or new user
    return_data = {
            "token": generate_jwt_token(email)
        }
    return request_success(return_data) # msg: Succeed.

def register(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))

    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return request_failed(1, "Invalid email", 400)
    user = User.objects.filter(email=email).first()
    password = require(body, "password", "string", err_msg="Missing or error type of [password]")
    name = require(body, "name", "string", err_msg="Missing or error type of [name]")
    if len(name) > 20 or name == "":
        return request_failed(-3, "Name too long", 400)
    if not re.match(r"[a-zA-Z0-9_]{1,20}", password):
        return request_failed(-4, "Password illegal", 400)
    if user is not None:
        if user.deleted:
            user.deleted = False
            user.save()
            return request_success({"message": "已恢复账户，请用原密码登录"})
        return request_failed(-1, "User already exists", 400)
    else:
        user = User(email=email, name=name, password=password)
        user.save()
        return_data = {
            "token": generate_jwt_token(email),
            "message": "注册成功"
        }
        return request_success(return_data)

def delete(req: HttpRequest):
    if req.method != "DELETE":
        return BAD_METHOD    
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(2, "Invalid or expired JWT", status_code=401) 
    user = User.objects.filter(email=payload["email"]).first()
    user.deleted = True
    user.save()
    return request_success({"message": "注销成功"})

def account_info(req: HttpRequest):
    if req.method == "GET":
        body = json.loads(req.body.decode("utf-8"))
        email = require(body, "email", "string", err_msg="Missing or error type of [email]")
        user = User.objects.filter(email=email).first()
        if user is None:
            return request_failed(-1, "用户不存在", 404)
        return_data = {
        "email": user.email,
        "name": user.name,
        "user_info": user.user_info,
        "avatar_path": user.avatar,
        "deleted": user.deleted,
        }
        return request_success(return_data)
    elif req.method == "PUT":
        invalid_email = False
        invalid_name = False
        jwt_token = req.headers.get("Authorization")
        if jwt_token == None or jwt_token == "":
            return request_failed(2, "Invalid or expired JWT", status_code=401)
        payload = check_jwt_token(jwt_token)
        if payload is None:
            return request_failed(2, "Invalid or expired JWT", status_code=401) 
        user = User.objects.filter(email=payload["email"]).first()
        body = json.loads(req.body.decode("utf-8"))
        newname = require(body, "name", "string", err_msg="Missing or error type of [name]")
        if len(newname) > 20 or newname == "":
            invalid_name = True
        else:
            user.name = newname
        newemail = require(body, "email", "string", err_msg="Missing or error type of [email]")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            invalid_email = True
        else:
            user.email = newemail
        user.user_info = require(body, "user_info", "string", err_msg="Missing or error type of [user_info]")
        user.avatar = require(body, "avatar_path", "string", err_msg="Missing or error type of [avatar_path]")
        user.save()
        if invalid_email:
            return request_failed(1, "Invalid email", 400)
        elif invalid_name:
            return request_failed(-3, "Name too long", 400)
        return request_success({"message": "修改成功"})
    else:
        return BAD_METHOD