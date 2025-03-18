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
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
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
    if not re.match(r"^[a-zA-Z0-9_]{1,20}$", password):
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
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401) 
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
    
@CheckRequire
def search_users(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    if req.method != "GET":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))
    
    query_email = require(body, "query_email", "string", err_msg="Missing or error type of [query_email]")
    query_name = require(body, "query_name", "string", err_msg="Missing or error type of [query_name]")

    query_filter = Q()
    if query_email:
        query_filter &= Q(email__icontains=query_email)
    if query_name:
        query_filter &= Q(name__icontains=query_name)

    else:
        return request_failed(-7, "Missing or error type of [query_email] or [query_name]", 400)

    # 执行查询
    users = User.objects.filter(query_filter, deleted=False)  # 只查询未注销用户

    if not users.exist():
        return request_failed(-1, "User not found or deleted", 404)
    
    result=[
        {
            "name": user.name,
            "email": user.email,
            "avatar_path": user.avatar.url if user.avatar else "",
        }
        for user in users
    ]

    return request_success(result)
    
@CheckRequire
def add_friend(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)
    
    if req.method != "POST":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))

    user_email = require(body, "user_email", "string", err_msg="Missing or error type of [user_email]")
    search_email = require(body, "search_email", "string", err_msg="Missing or error type of [search_email]")
    message = require(body, "message", "string", err_msg="Missing or error type of [message]")

    # 验证当前用户是否存在
    user_cur = User.objects.filter(email=user_email).first()
    if not user_cur:
        return request_failed(1, "User not found", 404)

    # 验证被添加用户是否存在
    user = User.objects.filter(email=search_email).first()
    if not user:
        return request_failed(1, "User not found", 404)
    
    # 验证当前用户是否已经是好友（通过会话conversation来判断是否为好友）
    existing_conversation = Conversation.objects.filter(
        type=0,  # 私聊类型
        members=user
    ).filter(members=user_cur).exists()  # 确保两个用户都在会话中

    if existing_conversation:
        return request_failed(-4, "Already friends", 403)
    
    new_request = Request(
        sender=user_cur,
        receiver=user,
        message=message if message else "Hello, I want to add you as a friend.",
    )

    new_request.save()

    return request_success({"message": "申请成功"})

@CheckRequire
def get_friend_requests(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)
    
    if req.method != "GET":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))

    user_email = require(body, "user_email", "string", err_msg="Missing or error type of [user_email]")

    friend_requests = Request.objects.filter(receiver__email=user_email).order_by("-time")  # 按申请时间降序排列

    # 构造返回的请求列表
    request_list = [
        {
            "user_email": req.sender.email,
            "user_name": req.sender.name,
            "avatar_path": req.sender.avatar.url if req.sender.avatar else "",
            "message": req.message,
            "created_at":req.time,
            "status": req.status
        }
        for req in friend_requests
    ]

    return request_success({"requests": request_list})

@CheckRequire
def friend_request_handle(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)
    
    if req.method not in ["POST", "DELETE"]:
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))
    sender_user_email = require(body, "sender_user_email", "string", err_msg="Missing or error type of [sender_user_email]")
    receiver_user_email = require(body, "receiver_user_email", "string", err_msg="Missing or error type of [receiver_user_email]")

    sender = User.objects.filter(email=sender_user_email, deleted=False).first()
    receiver = User.objects.filter(email=receiver_user_email, deleted=False).first()

    if not receiver:
        return request_failed(-1, "User deleted", 404)

    if req.method == "POST":
        # 处理好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()
        
        new_conversation = Conversation(
            type=0,  # 私聊类型
            members=[sender, receiver],
        )
        new_conversation.save()

        request.status = 2 
        request.save()

        return request_success({"message": "已接受"})

    elif req.method == "DELETE":
        # 拒绝好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()

        request.status = 1
        request.save()

        return request_success({"message": "已拒绝"})