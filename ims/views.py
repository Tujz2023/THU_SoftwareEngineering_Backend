import json
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.mail import send_mail
from django.template.loader import render_to_string
from ims.email import verification_email
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone

import random
import datetime
import string

from ims.models import (
    Conversation,
    User,
    Message,
    Request,
    Invitation,
    Group,
    Interface,
    Notification,
    Image
)
from utils.utils_request import (
    BAD_METHOD,
    request_failed,
    request_success,
    return_field,
)
from utils.utils_require import MAX_CHAR_LENGTH, CheckRequire, require
from utils.utils_time import get_timestamp, float2time, time2float
from utils.utils_jwt import generate_jwt_token, check_jwt_token
from utils.utils_crypto import encrypt_text, decrypt_text
import re


@CheckRequire
def login(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))

    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return request_failed(1, "Invalid email", 400)
    password = require(
        body, "password", "string", err_msg="Missing or error type of [password]"
    )
    user = User.objects.filter(email=email).first()
    if user is None:
        return request_failed(-1, "User not found", 404)
    elif user.deleted:
        return request_failed(1, "User deleted or not activated", 404)
    elif user.password != password:
        return request_failed(-3, "Wrong password", 401)
    # checking success or new user
    return_data = {"token": generate_jwt_token(user.id)}
    return request_success(return_data)  # msg: Succeed.

@CheckRequire
def register(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))

    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return request_failed(1, "Invalid email", 400)
    user = User.objects.filter(email=email).first()
    password = require(
        body, "password", "string", err_msg="Missing or error type of [password]"
    )
    name = require(body, "name", "string", err_msg="Missing or error type of [name]")
    if len(name) > 20 or name == "":
        return request_failed(-3, "Name too long", 400)
    if not re.match(r"^[a-zA-Z0-9_]{1,20}$", decrypt_text(password)):
        return request_failed(-4, "Password illegal", 400)
    if user is not None:
        if user.deleted:
            user.deleted = False
            user.password = password
            user.name = name
            user.save()
            return request_success(
                {"token": generate_jwt_token(user.id), "message": "已恢复账户"}
            )
        return request_failed(-1, "User already exists", 400)
    else:
        user = User(email=email, name=name, password=password, deleted=False)
        user.save()
        return_data = {"token": generate_jwt_token(user.id), "message": "注册成功"}
        return request_success(return_data)

@CheckRequire
def send_verification_email(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))

    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return request_failed(1, "Invalid email", 400)
    characters = string.digits  # 只使用数字
    code = "".join(random.choice(characters) for _ in range(6))
    verification = verification_email(code=code)
    try:
        success_count = send_mail(
            verification.subject,
            verification.plain_message,
            "instant_message@163.com",
            [email],
            html_message=verification.message,
        )
        if success_count == 1:
            return_data = {"verify_code": encrypt_text(code), "message": "发送成功"}
            return request_success(return_data)
        else:
            return request_failed(-5, "发送失败，请检查网络和邮箱", status_code=404)
    except:
        return request_failed(-5, "发送失败，请检查网络和邮箱", status_code=404)


@CheckRequire
def delete(req: HttpRequest):
    if req.method != "DELETE":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    user = User.objects.filter(id=payload["id"]).first()
    user.deleted = True
    user.save()
    return request_success({"message": "注销成功"})


@CheckRequire
def account_info(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    user = User.objects.filter(id=payload["id"]).first()
    # if jwt is valid, user must exist
    if req.method == "GET":
        return_data = {
            "email": user.email,
            "name": user.name,
            "user_info": user.user_info,
            "avatar": user.avatar,
            "deleted": user.deleted,
            "id": user.id,
        }
        return request_success(return_data)
    elif req.method == "PUT":
        invalid_email = False
        invalid_name = False
        invalid_pass = False

        body = json.loads(req.body.decode("utf-8"))
        origin_password = body["origin_password"]
        if origin_password != user.password:
            return request_failed(-3, "密码错误", 401)

        if "name" in body:
            newname = require(
                body, "name", "string", err_msg="Missing or error type of [name]"
            )
            if len(newname) > 20 or newname == "":
                invalid_name = True
            else:
                user.name = newname
        if "email" in body:
            newemail = require(
                body, "email", "string", err_msg="Missing or error type of [email]"
            )
            if not re.match(r"[^@]+@[^@]+\.[^@]+", newemail):
                invalid_email = True
            else:
                user.email = newemail
        if "password" in body:
            newpassword = require(
                body,
                "password",
                "string",
                err_msg="Missing or error type of [password]",
            )
            if not re.match(r"^[a-zA-Z0-9_]{1,20}$", decrypt_text(newpassword)):
                invalid_pass = True
            user.password = newpassword

        if "user_info" in body:
            user.user_info = require(
                body,
                "user_info",
                "string",
                err_msg="Missing or error type of [user_info]",
            )
        if "avatar" in body:
            user.avatar = require(
                body, "avatar", "string", err_msg="Missing or error type of [avatar]"
            )
        user.save()
        if invalid_email:
            return request_failed(1, "Invalid email", 400)
        if invalid_name:
            return request_failed(-3, "Name too long", 400)
        if invalid_pass:
            return request_failed(-4, "Invalid password", 400)
        return request_success({"message": "修改成功"})
    else:
        return BAD_METHOD


@CheckRequire
def search_users(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    user_cur = User.objects.filter(id=payload["id"]).first()

    if req.method != "GET":
        return BAD_METHOD

    query_name = req.GET.get("query_name", "")
    if query_name == "":
        return request_failed(-7, "Missing or error type of [query_name]", 400)

    # 执行查询
    users = User.objects.filter(name=query_name, deleted=False)  # 只查询未注销用户

    if not users.exists():
        result = []
        return request_success({"results": result})

    result = [
        {
            "user_id": user.id,
            "name": user.name,
            "email": user.email,
            "avatar": user.avatar,
            "is_friend": False if user == user_cur else Conversation.objects.filter(type=0).filter(members=user_cur).filter(members=user).exists(),
            "deleted": user.deleted,
        }
        for user in users
    ]

    return request_success({"results": result})

@CheckRequire
def add_friend(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method != "POST":
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))

    target_id = require(body, "target_id", "int", err_msg="Missing or error type of [target_id]")
    message = require(body, "message", "string", err_msg="Missing or error type of [message]")

    user_cur = User.objects.filter(id=payload["id"]).first()

    # 验证被添加用户是否存在
    user = User.objects.filter(id=target_id).first()

    if user == user_cur:
        return request_failed(-6, "Can not add yourself as friend", 403)

    if not user:
        return request_failed(-1, "User not found or deleted", 404)
    if user.deleted == True:
        return request_failed(-1, "User not found or deleted", 404)

    # 验证当前用户是否已经是好友（通过会话conversation来判断是否为好友）
    existing_conversation = Conversation.objects.filter(
        type=0  # 私聊类型
    ).filter(members=user).filter(members=user_cur).exists()

    if existing_conversation:
        return request_failed(-4, "Already friends", 403)

    # 验证是否已经发送过好友请求
    existing_request = Request.objects.filter(
        sender=user_cur, receiver=user, status=0
    ).exists()

    if existing_request:
        return request_failed(-5, "Friend request already sent", 403)
    
    if Request.objects.filter(sender=user_cur, receiver=user).exists():
        new_request = Request.objects.filter(sender=user_cur, receiver=user).first()
        new_request.status = 0
        new_request.message = message if message else "Hello, I want to add you as a friend."
        new_request.time = get_timestamp()
    else:
        new_request = Request(
            sender=user_cur,
            receiver=user,
            message=message if message else "Hello, I want to add you as a friend.",
        )

    new_request.save()

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        str(target_id),{"type": "request_message"}
    )

    return request_success({"message": "申请成功"})

@CheckRequire
def get_friend_requests(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method != "GET":
        return BAD_METHOD

    user_email = User.objects.filter(id=payload["id"]).first().email

    cur_user_id = User.objects.filter(email=user_email).first().id

    if not Request.objects.filter(receiver__email=user_email).exists():
        request_list = []
        return request_success({"requests": request_list})
    
    friend_requests = Request.objects.filter(receiver__email=user_email).order_by("-time")  # 按申请时间降序排列

    # 构造返回的请求列表
    request_list = [
        {
            "sender_user_id": req.sender.id,
            "receiver_user_id": cur_user_id,
            "user_email": req.sender.email,
            "user_name": req.sender.name,
            "avatar": req.sender.avatar,
            "message": req.message,
            "created_at": float2time(req.time),
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

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method not in ["POST", "DELETE"]:
        return BAD_METHOD

    body = json.loads(req.body.decode("utf-8"))
    sender_user_id = require(body, "sender_user_id", "int", err_msg="Missing or error type of [sender_user_id]")
    receiver_user_id = require(body, "receiver_user_id", "int", err_msg="Missing or error type of [receiver_user_id]")
    
    sender = User.objects.filter(id=sender_user_id).first()
    receiver = User.objects.filter(id=receiver_user_id).first()
    
    if not receiver or receiver.deleted == True:
        return request_failed(-1, "User deleted", 404)
    if not sender or sender.deleted == True:
        return request_failed(-1, "User deleted", 404)
    
    if not Request.objects.filter(sender=sender, receiver=receiver).exists():
        return request_failed(-5, "Request not found", 403)

    if Conversation.objects.filter(type=0).filter(members=sender).filter(members=receiver).exists():
        return request_failed(-4, "Already friends", 403)

    if req.method == "POST":
        # 处理好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()
        request.status = 1
        request.save()

        if Request.objects.filter(sender=receiver, receiver=sender, status=0).exists():
            another_request = Request.objects.filter(sender=receiver, receiver=sender, status=0).first()
            another_request.status = 3
            another_request.save()

        new_conversation = Conversation(type=0)
        new_conversation.save()
        new_conversation.members.add(sender, receiver)

        new_itf = Interface.objects.create(conv=new_conversation, user=sender)
        new_itf.save()
        new_itf2 = Interface.objects.create(conv=new_conversation, user=receiver)
        new_itf2.save()

        new_message = Message(content="我已经同意你的好友请求，可以开始聊天了~~", type=0, sender=receiver, conversation=new_conversation)
        new_message.save()
        channel_layer = get_channel_layer()
        for member in new_conversation.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=new_conversation, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})

        return request_success({"message": "已接受好友申请"})

    elif req.method == "DELETE":
        # 拒绝好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()

        request.status = 2
        request.save()

        return request_success({"message": "已拒绝该好友申请"})


@CheckRequire
def groups(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method not in ["GET", "POST"]:
        return BAD_METHOD
    # 获取群组列表
    if req.method == "GET":
        user_email = User.objects.filter(id=payload["id"]).first().email
        groups = Group.objects.filter(owner__email=user_email)
        if not groups.exists():
            return request_success({"groups": []})
        group_list = [
            {
                "id": group.id,
                "name": group.name,
            }
            for group in groups
        ]
        return request_success({"groups": group_list})

    # 创建群组
    elif req.method == "POST":
        user = User.objects.filter(id=payload['id']).first()
        user_email = user.email
        body = json.loads(req.body.decode("utf-8"))
        name = require(body, "name", "string", err_msg="Missing or error type of [name]")
        if name == '':
            return request_failed(-2, "Missing or error type of [name]", 400)

        existing_group = Group.objects.filter(owner__email=user_email, name=name).first()
        if existing_group:
            return request_failed(-1, "Group already exists", 409)

        new_group = Group.objects.create(owner=user, name=name)
        new_group.save()

        return request_success({"message": "分组创建成功"})

@CheckRequire
def manage_groups(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method not in ["GET", "PUT", "DELETE"]:
        return BAD_METHOD

    # 查看分组详情
    if req.method == "GET":
        group_id = req.GET.get("group_id", "")
        group = Group.objects.filter(id=int(group_id)).first()
        if not group:
            return request_failed(-1, "Group not found", 404)

        group_members = [
            {
                "id": member.id,
                "email": member.email,
                "name": member.name,
                "avatar": member.avatar,
                # "avatar": "true" if member.avatar else "false",
                "deleted": member.deleted
            }
            for member in group.members.all()
        ]

        result = {
            "id": group.id,
            "name": group.name,
            "members": group_members,
        }

        return request_success({"group": result})

    # 修改分组名称
    elif req.method == "PUT":
        body = json.loads(req.body.decode("utf-8"))
        user_email = User.objects.filter(id=payload["id"]).first().email
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")
        new_name = require(body, "new_name", "string", err_msg="Missing or error type of [new_name]")

        exsiting_group = Group.objects.filter(owner__email=user_email, name=new_name).first()
        if exsiting_group and exsiting_group.id != int(group_id):
            return request_failed(-1, "Name already exists", 409)

        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-1, "Group not found", 404)

        group.name = new_name
        group.save()

        return request_success({"message": "修改分组名称成功"})

    # 删除分组
    elif req.method == "DELETE":
        user_email = User.objects.filter(id=payload["id"]).first().email
        body = json.loads(req.body.decode("utf-8"))
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")

        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-1, "Group not found", 404)

        group.delete()
        return request_success({"message": "删除分组成功"})


@CheckRequire
def manage_group_members(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method not in ["GET", "POST", "DELETE"]:
        return BAD_METHOD

    # 查看分组成员列表
    if req.method == "GET":
        group_id = req.GET.get("group_id", "")
        group = Group.objects.filter(id=int(group_id)).first()
        if not group:
            return request_failed(-1, "Group not found", 404)

        group_members = [
            {
                "id": member.id,
                "email": member.email,
                "name": member.name,
                "avatar": member.avatar,
                # "avatar": "True" if member.avatar else "False",
                "deleted": member.deleted
            }
            for member in group.members.all()
        ]

        return request_success({"members": group_members})

    # 添加分组成员
    elif req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")
        member_id = require(body, "member_id", "int", err_msg="Missing or error type of [member_id]")

        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-3, "Group not found", 404)

        member = User.objects.filter(id=member_id).first()
        user = User.objects.filter(id=payload['id']).first()
        if not Conversation.objects.filter(type=0).filter(members=user).filter(members=member).exists():
            return request_failed(-1, "Member is not friend", 404)

        if group.members.filter(id=member_id).exists():
            return request_failed(-3, "Member already in group", 400)

        group.members.add(member)

        return request_success({"message": "添加分组成员成功"})

    # 删除分组成员
    elif req.method == "DELETE":
        body = json.loads(req.body.decode("utf-8"))
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")
        member_id = require(body, "member_id", "int", err_msg="Missing or error type of [member_id]")

        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-3, "Group not found", 404)

        member = User.objects.filter(id=member_id).first()

        if not group.members.filter(id=member_id).exists():
            return request_failed(-3, "Member not in group", 400)

        group.members.remove(member)
        return request_success({"message": "删除分组成员成功"})


@CheckRequire
def get_friends_list(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method != "GET":
        return BAD_METHOD

    user_email = User.objects.filter(id=payload["id"]).first().email

    if not Conversation.objects.filter(type=0).filter(members__email=user_email).exists():
        friends_list = []
        return request_success({"friends": friends_list})

    # 从对话中获取好友列表中好友的email列表
    conv = Conversation.objects.filter(type=0).filter(members__email=user_email)
    
    friends = User.objects.filter(conversation__in=conv).exclude(id=payload["id"]).distinct()

    friends_list = [
        {
            "id": friend.id,
            "email": friend.email,
            "name": friend.name,
            "avatar": friend.avatar,
            "deleted": friend.deleted
        }
        for friend in friends
    ]

    return request_success({"friends": friends_list})

@CheckRequire
def search_user_detail(req: HttpRequest):
    if req.method != "GET":
        return BAD_METHOD
    
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    cur_user = User.objects.filter(id=payload["id"]).first()
    user_id = req.GET.get("userId", "")
    user = User.objects.filter(id=user_id).first()
    if not user:
        return request_failed(-1, "User not found", 404)
    
    # 判断用户是否为自己的好友
    if not Conversation.objects.filter(type=0).filter(members=cur_user).filter(members=user).exists():
        is_friend = False
    else:
        is_friend = True

    return_data = {
        "name": user.name,
        "email": user.email,
        "avatar": user.avatar,
        "is_deleted": user.deleted,
        "is_friend": is_friend,
    }

    return request_success({"user": return_data})


@CheckRequire
def manage_friends(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method not in ["GET", "PUT", "DELETE"]:
        return BAD_METHOD

    # 查看好友详情
    if req.method == "GET":
        friend_id = req.GET.get("friend_id", "")

        user = User.objects.filter(id=payload['id']).first()
        if not user:
            return request_failed(-1, "User not found", 404)

        friend = User.objects.filter(id=friend_id).first()
        if not friend:
            return request_failed(-1, "Friend not found", 404)
        if not Conversation.objects.filter(type=0).filter(members=friend).filter(members=user).exists():
            return request_failed(-1, "Friend not found", 404)

        friend_groups = Group.objects.filter(owner=user, members=friend)

        return_data = {
            "id": friend.id,
            "email": friend.email,
            "name": friend.name,
            "avatar": friend.avatar,
            # "avatar": "true" if friend.avatar else "false",
            "user_info": friend.user_info,
            "deleted": friend.deleted,
            "groups": [
                {
                    "id": group.id,
                    "name": group.name,
                }
                for group in friend_groups
            ]
        }

        return request_success(return_data)

    # 删除好友
    if req.method == "DELETE":
        body = json.loads(req.body.decode("utf-8"))
        user_id = payload["id"]
        friend_id = require(body, "friend_id", "int", err_msg="Missing or error type of [friend_id]")
        
        user = User.objects.filter(id=user_id).first()
        friend = User.objects.filter(id=friend_id).first()

        if not friend:
            return request_failed(-1, "Friend not found", 404)
        
        if not Conversation.objects.filter(type=0).filter(members=user).filter(members=friend).exists():
            return request_failed(-3, "Already not friend", 404)

        Conversation.objects.filter(type=0).filter(members=user).filter(members=friend).delete()

        # 删除好友之间的请求
        Request.objects.filter(sender=user, receiver=friend).delete()
        Request.objects.filter(sender=friend, receiver=user).delete()

        # 删除其所在分组的信息
        if Group.objects.filter(owner=user).filter(members=friend).exists():
            groups = Group.objects.filter(owner=user).filter(members=friend).all()
            for group in groups:
                group.members.remove(friend)

        if Group.objects.filter(owner=friend).filter(members=user).exists():
            groups = Group.objects.filter(owner=friend).filter(members=user).all()
            for group in groups:
                group.members.remove(user)
        
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            str(friend.id),{"type": "delete_friend"}
        )
        async_to_sync(channel_layer.group_send)(
            str(user.id),{"type": "delete_friend"}
        )

        return request_success({"message": "删除好友成功"})

@CheckRequire
def conversation(req: HttpRequest):
    if req.method not in ["GET", "POST"]:
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id = payload["id"]).first()

    if req.method == "GET":
        if not Interface.objects.filter(user=cur_user).exists():
            return request_success({"conversation": []})
        itfs = Interface.objects.filter(user = cur_user).all()
        convs = []
        for itf in itfs:
            conv = itf.conv
            if Message.objects.filter(id=itf.last_message_id).exists():
                last_message = Message.objects.filter(id=itf.last_message_id).first()
                last_content = last_message.content
                last_message_time = last_message.time
                last_message_type = last_message.type
            else:
                last_content = ""
                last_message_time = 0
                last_message_type = 0
            if conv.type == 1:
                name = conv.ConvName
                avatar = conv.avatar
            else:
                user = conv.members.exclude(id=cur_user.id).first()
                name = user.name
                avatar = user.avatar
            new_return = {
                "id": conv.id,
                "name": name,
                # "avatar": True if avatar else False,
                "avatar": avatar,
                "last_message": last_content,
                "last_message_type": last_message_type,
                "last_message_time": last_message_time,
                "is_chat_group": True if conv.type == 1 else False,
                "is_top": itf.ontop,
                "notice_able": itf.notification,
                "unread_count": itf.unreads
            }
            if conv.type == 0:
                new_return['friend_id'] = user.id
            convs.append(new_return)
        sorted_convs = sorted(convs, key=lambda conv: (not conv['is_top'], -conv['last_message_time']))
        for conv in sorted_convs:
            conv['last_message_time'] = "" if conv['last_message_time'] == 0 else float2time(conv['last_message_time'])
        return request_success({"conversation": sorted_convs})
    elif req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        members = require(body, "members", "list", err_msg="Missing or error type of [members]")
        name = require(body, "name", "string", err_msg="Missing or error type of [name]")
        for member in members:
            if not User.objects.filter(id=member).exists():
                return request_failed(-1, "User not found", 404)
            member_user = User.objects.filter(id=member).first()
            if not Conversation.objects.filter(
            type=0  # 私聊类型
            ).filter(members=member_user).filter(members=cur_user).exists():
                return request_failed(-3, "Not friend with current user.", 400)
            
        new_conv = Conversation(type=1, ConvName=name, creator=cur_user)
        new_conv.save()
        for member in members:
            member_user = User.objects.filter(id=member).first()
            mem_interface = Interface(conv=new_conv, user=member_user)
            mem_interface.save()
            new_conv.members.add(member_user)

        new_conv.members.add(cur_user)
        cur_interface = Interface(conv=new_conv, user=cur_user)
        cur_interface.save()

        channel_layer = get_channel_layer()
        new_message = Message(content="欢迎大家，我们可以聊天了~~", type=0, sender=cur_user, conversation=new_conv)
        new_message.save()
        for member in new_conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=new_conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})
        return request_success({"message": "创建会话成功"})

@CheckRequire
def message(req: HttpRequest):
    if req.method not in ["POST", "GET", "DELETE"]:
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    
    if req.method == "DELETE":# 这个是彻底删除所有聊天记录
        body = json.loads(req.body.decode("utf-8"))
        msgid = require(body, "message_id", "int", err_msg="Missing or error type of [message_id]")
        if not Message.objects.filter(id=msgid).exists():
            return request_failed(-1, "Message not found", 404)
        msg = Message.objects.filter(id=msgid).first()
        if cur_user not in msg.conversation.managers.all() and msg.sender != cur_user and cur_user != msg.conversation.creator:
            return request_failed(-3, "No permission to delete message", 403)
        msg.delete()
        return request_success({"message": "删除聊天记录成功"})
    
    if req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        conv_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversation_id]")
        conv = Conversation.objects.filter(id=conv_id).first()

        if not conv:
            return request_failed(-1, "Conversation not found", 404)
        if cur_user not in Conversation.objects.filter(id=conv_id).first().members.all():
            return request_failed(1, "Not in conversation", 400)
        
        content = require(body, "content", "string", err_msg="Missing or error type of [content]")
        if content == "":
            return request_failed(-3, "Content is empty", 400)
        if len(content) > MAX_CHAR_LENGTH:
            return request_failed(-3, "Content is too long", 400)
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            if not itf:
                return request_failed(-1, "Interface not found", 404)
            
        if "reply_to" in body:
            reply_to_id = require(body, "reply_to", "int", err_msg="Error type of [reply_to]")
            if not Message.objects.filter(id=reply_to_id).exists():
                return request_failed(-4, "Reply message not found", 400)
            reply_to = Message.objects.filter(id=reply_to_id).first()
            if reply_to.conversation != conv:
                return request_failed(-4, "Reply message not found", 400)
            new_message = Message(content=content, type=0, sender=cur_user, conversation=conv, reply_to=reply_to)
        else:
            new_message = Message(content=content, type=0, sender=cur_user, conversation=conv)
        new_message.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            if member == cur_user:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'true'})
            else:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})

        return request_success({"message": "成功发送"})
    
    elif req.method == "GET":
        conv_id = int(req.GET.get('conversationId'))
        conv = Conversation.objects.filter(id=conv_id).first()

        if not conv:
            return request_failed(-1, "Conversation not found", 404)
        if cur_user not in Conversation.objects.filter(id=conv_id).first().members.all():
            return request_failed(1, "Not in conversation", 400)

        timestring = req.GET.get('from', '0')
        if timestring != '0':
            timestamp = time2float(timestring)
        else:
            timestamp = 0
        
        messages = Message.objects.filter(conversation=conv).exclude(invisible_to=cur_user).filter(time__gte=timestamp).order_by('time')
        itf = Interface.objects.filter(conv=conv, user=cur_user).first()
        itf.unreads = 0
        itf.save()

        return_message = []
        for msg in messages:
            ret = msg.serialize()
            if (msg.reply_to != None) and (not msg.reply_to.invisible_to.filter(id=cur_user.id).exists()):
                ret['reply_to'] = msg.reply_to.content
                ret['reply_to_id'] = msg.reply_to.id
                ret['reply_to_type'] = msg.reply_to.type
            if (msg.sender != cur_user) and (not msg.read_by.filter(id=cur_user.id).exists()):
                msg.read_by.add(cur_user)
            if conv.type == 0:
                if msg.read_by.exclude(id=cur_user.id).exists():
                    ret['already_read'] = True
                else:
                    ret['already_read'] = False
            return_message.append(ret)
        return request_success({"messages": return_message})

@CheckRequire
def delete_messages(req: HttpRequest):
    if req.method != "DELETE":
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    
    body = json.loads(req.body.decode("utf-8"))
    message_ids = require(body, "message_ids", "list", err_msg="Missing or error type of [message_list]")
    last_time = 0
    last_id = -1
    for msg_id in message_ids:
        if not Message.objects.filter(id=msg_id).exists():
            return request_failed(-1, "Message not found", 404)
        msg = Message.objects.filter(id=msg_id).first()
        msg.invisible_to.add(cur_user)
        if msg.time > last_time:
            last_time = msg.time
            last_id = msg.id
    
    first_msg = Message.objects.filter(id=message_ids[0]).first()
    conv = first_msg.conversation
    itf = Interface.objects.filter(conv=conv, user=cur_user).first()
    if last_id == itf.last_message_id: 
        last_message = Message.objects.filter(conversation=conv).exclude(invisible_to=cur_user)
        if not last_message.exists():
            itf.last_message_id = -1
        else:
            itf.last_message_id = last_message.order_by('-time').first().id
            # print("last_id: ", last_id, "itf_last_id: ", itf.last_message_id)
            # input()
        itf.save()
    
    return request_success({"message": "删除聊天记录成功"})

@CheckRequire
def image(req: HttpRequest):
    if req.method not in ["POST"]:
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    
    if "conversationId" in req.POST and "image" in req.FILES:
        conv_id = req.POST['conversationId']
        conv = Conversation.objects.filter(id=conv_id).first()

        if not conv:
            return request_failed(-1, "Conversation not found", 404)
        if cur_user not in Conversation.objects.filter(id=conv_id).first().members.all():
            return request_failed(1, "Not in conversation", 400)
        
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            if not itf:
                return request_failed(-1, "Interface not found", 404)

        file = req.FILES['image']
            
        new_message = Message(content="", type=1, sender=cur_user, conversation=conv)
        new_message.save()
        image = Image(image=file, message=new_message)
        image.save()
        new_message.content = req.build_absolute_uri(image.image.url)
        new_message.save()

        channel_layer = get_channel_layer()
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            if member == cur_user:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'true'})
            else:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})

        return request_success({"message": "成功发送"})

@CheckRequire
def get_reply(req: HttpRequest):
    if req.method != "GET":
        return BAD_METHOD
    
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()

    msgid = int(req.GET.get("message_id", ""))
    if not Message.objects.filter(id=msgid).exists():
        return request_failed(-1, "Message not found", 404)
    
    replies = Message.objects.filter(reply_to_id=msgid).exclude(invisible_to=cur_user).order_by('time')
    return_message = []
    
    for msg in replies:
        return_message.append({
            "reply_id": msg.id,
            "reply_type": msg.type,
            "sender_id": msg.sender.id,
            "sender_name": msg.sender.name,
            # "sender_avatar": True if msg.sender.avatar else False,
            "sender_avatar": msg.sender.avatar,
            "content": msg.content,
            "time": float2time(msg.time),
        })
    return request_success({"replies": return_message})

@CheckRequire
def get_members(req: HttpRequest):
    if req.method != "GET":
        return BAD_METHOD
    
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    
    conv_id = int(req.GET.get("conversation_id", ""))
    if not Conversation.objects.filter(id=conv_id).exists():
        return request_failed(-1, "Conversation not found", 404)

    conv = Conversation.objects.filter(id=conv_id).first()
    if not conv.members.filter(id=cur_user.id).exists():
        return request_failed(-1, "Conversation not found", 404)
    return_members = []
    if conv.type == 0:
        # 私聊情况只返回对方的用户信息
        member = conv.members.exclude(id=payload["id"]).first()
        return request_success({"members": [{"id": member.id, "name": member.name, "avatar": member.avatar}]})
    else:
        # 群聊情况返回所有成员的用户信息
        for member in conv.members.all():
            temp_identity = 3
            if conv.creator == member:
                temp_identity = 1
            elif conv.managers.filter(id=member.id).exists():
                temp_identity = 2
            return_members.append({
                "id": member.id,
                "name": member.name,
                # "avatar": True if member.avatar else False,
                "avatar": member.avatar,
                "identity": temp_identity
            })
        return_members = sorted(return_members, key=lambda x: x['identity'])
        identity = 3
        if conv.creator.id == payload["id"]:
            identity = 1
        elif conv.managers.filter(id=payload["id"]).exists():
            identity = 2
        return request_success({"identity": identity, "members": return_members})

@CheckRequire
def conv_manage_admin(req: HttpRequest):
    if req.method not in ["POST", "DELETE"]:
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    body = json.loads(req.body.decode("utf-8"))
    conversation_id = require(body, "conversation_id", "int", err_msg="Missing or error type of [conversation_id]")
    conv = Conversation.objects.filter(id=conversation_id).first()
    if not conv:
        return request_failed(-1, "Conversation not found", 404)
    if conv.creator != cur_user:
        return request_failed(-3, "非群主不能设置管理员", 403)
    set_user_id = require(body, "user", "int", err_msg="Missing or error type of [user]")
    set_user = User.objects.filter(id=set_user_id).first()
    if not set_user:
        return request_failed(-1, "User not found", 404)
    if set_user == cur_user:
        return request_failed(3, "不能设置自己为管理员", 403)
    if set_user not in conv.members.all():
        return request_failed(1, "User not in conversation", 400)
    if req.method == "POST":
        if set_user in conv.managers.all():
            return request_failed(3, "成员已经是管理员", 403)
        conv.managers.add(set_user)
        conv.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():
            async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'modify_members', 'conversationId': str(conv.id)})
        return request_success({"message":"设置群组管理员成功"})
    elif req.method == "DELETE":
        if set_user not in conv.managers.all():
            return request_failed(3, "成员不是管理员", 403)
        conv.managers.remove(set_user)
        conv.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():
            async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'modify_members', 'conversationId': str(conv.id)})
        return request_success({"message":"解除群组管理员成功"})
        
@CheckRequire
def conv_manage_info(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    body = json.loads(req.body.decode("utf-8"))
    conversation_id = require(body, "conversation_id", "int", err_msg="Missing or error type of [conversation_id]")
    conv = Conversation.objects.filter(id=conversation_id).first()
    if not conv:
        return request_failed(-1, "Conversation not found", 404)
    if conv.creator != cur_user and cur_user not in conv.managers.all():
        return request_failed(-3, "非群主或管理员不能修改群信息", 403)

    if 'name' in body:
        name = require(body, "name", "string", err_msg="Missing or error type of [name]")
        conv.ConvName = name
    if 'avatar' in body:
        avatar = require(body, "avatar", "string", err_msg="Missing or error type of [avatar]")
        conv.avatar = avatar
    conv.save()
    channel_layer = get_channel_layer()
    for member in conv.members.all():
        async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'conv_setting'})
    return request_success({"message":"修改群信息成功"})
    
@CheckRequire
def conv_manage_ownership(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()

    body = json.loads(req.body.decode("utf-8"))
    conversation_id = require(body, "conversation_id", "int", err_msg="Missing or error type of [conversation_id]")
    set_user_id = require(body, "user", "int", err_msg="Missing or error type of [uid]")

    conv = Conversation.objects.filter(id=conversation_id).first()
    if not conv:
        return request_failed(-1, "Conversation not found", 404)
    if conv.creator != cur_user:
        return request_failed(-3, "非群主不能转让群主", 403)
    
    set_user = User.objects.filter(id=set_user_id).first()
    if not set_user:
        return request_failed(-1, "User not found", 404)
    if set_user not in conv.members.all():
        return request_failed(1, "User not in conversation", 400)
    if set_user == cur_user:
        return request_failed(-3, "不能转让给自己", 403)
    if set_user in conv.managers.all():
        conv.managers.remove(set_user)
    conv.creator = set_user
    conv.save()
    channel_layer = get_channel_layer()
    for member in conv.members.all():
        async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'modify_members', 'conversationId': str(conv.id)})
    return request_success({"message":"群主转让成功"})

@CheckRequire
def conv_member_remove(req: HttpRequest):
    if req.method not in ["POST", "DELETE"]:
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()

    body = json.loads(req.body.decode("utf-8"))
    conversation_id = require(body, "conversation_id", "int", err_msg="Missing or error type of [conversation_id]")
    conv = Conversation.objects.filter(id=conversation_id).first()

    if not conv:
        return request_failed(-1, "Conversation not found", 404)
    if req.method == "POST":
        if cur_user not in conv.members.all():
            return request_failed(-1, "你不在群组中，无法退出", 400)
        if cur_user == conv.creator:
            channel_layer = get_channel_layer()
            for member in conv.members.all():
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'remove_members'})
            conv.delete()
            return request_success({"message":"群组解散成功"})
        conv.members.remove(cur_user)
        if cur_user in conv.managers.all():
            conv.managers.remove(cur_user)
        conv.save()

        itf = Interface.objects.filter(conv=conv, user=cur_user).first()
        itf.delete()
        for msg in Message.objects.filter(conversation=conv).all():
            if cur_user in msg.invisible_to.all():
                msg.invisible_to.remove(cur_user)
            if cur_user in msg.read_by.all():
                msg.read_by.remove(cur_user)
            msg.save()
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(str(cur_user.id), {'type': 'remove_members'})
        
        return request_success({"message":"退出群组成功"})
    elif req.method == "DELETE":
        if conv.creator != cur_user and cur_user not in conv.managers.all():
            return request_failed(-3, "非群主或管理员不能移除群成员", 403)
        set_user_id = require(body, "user", "int", err_msg="Missing or error type of [user]")
        set_user = User.objects.filter(id=set_user_id).first()
        if not set_user:
            return request_failed(-1, "User not found", 404)
        if set_user not in conv.members.all():
            return request_failed(1, "User not in conversation", 400)
        if set_user in conv.managers.all() and cur_user != conv.creator:
            return request_failed(-3, "非群主不能移除管理员", 403)
        conv.members.remove(set_user)
        if set_user in conv.managers.all():
            conv.managers.remove(set_user)
        conv.save()

        itf = Interface.objects.filter(conv=conv, user=set_user).first()
        itf.delete()
        for msg in Message.objects.filter(conversation=conv).all():
            if set_user in msg.invisible_to.all():
                msg.invisible_to.remove(set_user)
            if set_user in msg.read_by.all():
                msg.read_by.remove(set_user)
            msg.save()
        
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(str(set_user_id), {'type': 'remove_members'})
        for member in conv.members.all():
            async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'modify_members', 'conversationId': str(conv.id)})
        return request_success({"message":"移除群成员成功"})
    
@CheckRequire
def conv_member_add(req: HttpRequest):
    if req.method != "POST":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    cur_user = User.objects.filter(id=payload["id"]).first()
    body = json.loads(req.body.decode("utf-8"))
    conversation_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversation_id]")
    member_id = require(body, "member_id", "int", err_msg="Missing or error type of [member_id]")

    conv = Conversation.objects.filter(id=conversation_id).first()

    existing_member = conv.members.filter(id=member_id).first()# 检查是否已经在群聊中
    if existing_member:
        return request_failed(-3, "The member is already in the conversation", 403)
    
    member = User.objects.filter(id=member_id).first()# 检查是不是自己的好友
    if not Conversation.objects.filter(type=0).filter(members=member).filter(members=cur_user).exists():
        return request_failed(-4, "The user is not your friend", 403)
    
    if Invitation.objects.filter(sender=cur_user, receiver=member, conversation=conv, status=0).exists():
        return request_failed(-5, "正在等待管理员确认，请不要重复发送", 403)

    if Invitation.objects.filter(sender=cur_user, receiver=member, conversation=conv).exists():
        invitation = Invitation.objects.filter(sender=cur_user, receiver=member, conversation=conv).first()
        invitation.status = 0
    else:
        invitation = Invitation(
            sender=cur_user,
            receiver=member,
            conversation=conv,
            status=0 # waiting
        )

    invitation.save()

    if cur_user == conv.creator or conv.managers.filter(id=cur_user.id).exists():
        invitation.status = 2 # accepted
        invitation.save()
        conv.members.add(invitation.receiver)
        conv.save()
        itf = Interface(conv=conv, user=invitation.receiver)
        itf.save()

        invs = Invitation.objects.filter(receiver=invitation.receiver).exclude(id=invitation.id).all()
        for inv in invs:
            inv.status = 3
            inv.save()

        member = invitation.receiver
        new_message = Message(content=f"欢迎新成员~~\n\n{member.name}成功加入了我们，让我们一起欢迎他 ^o^", type=0, sender=cur_user, conversation=conv)
        new_message.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            if member == cur_user:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'true'})
            else:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "invitation_message",
                    "conversationId": str(conv.id)
                }
            )
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "modify_members",
                    "conversationId": str(conv.id)
                }
            )
        
        return request_success({"message": "邀请成功"})
    else:
        # invitation的websocket
        channel_layer = get_channel_layer()
        for member in conv.members.all():
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "invitation_message",
                    "conversationId": str(conv.id)
                }
            )

        return request_success({"message": "邀请成功，等待管理员确认"})

@CheckRequire
def conv_invitation(req: HttpRequest):# 用于所有群成员查看邀请，但是只有群主和管理员可以处理（handle函数）
    if req.method != "GET":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    conversation_id = int(req.GET.get("conversation_id", ""))
    conv = Conversation.objects.filter(id=conversation_id).first()

    if not conv:
        return request_failed(-1, "Conversation not found", 404)
    cur_user = User.objects.filter(id=payload["id"]).first()
    if cur_user not in conv.members.all():
        return request_failed(-1, "Conversation not found", 404)
        
    invitations_list = Invitation.objects.filter(conversation=conv).order_by("-time")

    if not invitations_list.exists():
        return request_success({"invitations": []})
    
    invitations= []
    for invitation in invitations_list:
        invitations.append({
            "invite_id": invitation.id,
            "conversation_id": invitation.conversation.id,
            "sender_id": invitation.sender.id,
            "sender_name": invitation.sender.name,
            "sender_avatar": invitation.sender.avatar,
            # "sender_avatar": True if invitation.sender.avatar else False,
            "receiver_id": invitation.receiver.id,
            "receiver_name": invitation.receiver.name,
            "receiver_avatar": invitation.receiver.avatar,
            # "receiver_avatar": True if invitation.receiver.avatar else False,
            "timestamp": float2time(invitation.time),
            "status": invitation.status,
        })

    return request_success({"invitations": invitations})
    
@CheckRequire
def conv_handle_invitation(req: HttpRequest):
    if req.method not in ["POST", "DELETE"]:
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)

    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    cur_user = User.objects.filter(id=payload["id"]).first()
    body = json.loads(req.body.decode("utf-8"))
    invitation_id = require(body, "invite_id", "int", err_msg="Missing or error type of [invite_id]")
    invitation = Invitation.objects.filter(id=invitation_id).first()

    if not invitation:
        return request_failed(-5, "Invitation not found", 403)

    conv = invitation.conversation
    status = invitation.status

    is_creator = (conv.creator.id == cur_user.id)
    is_admin = conv.managers.filter(id=cur_user.id).exists()

    if not is_creator and not is_admin:
        return request_failed(-3, "非群主或管理员不能处理邀请", 403)

    if status != 0:
        return request_failed(-4, "邀请已处理", 403)
    
    existing_member = conv.members.filter(id=invitation.receiver.id).first()# 检查是否已经在群聊中
    if existing_member:
        return request_failed(-6, "User already in conversation", 403)
    
    if req.method == "POST":
        invitation.status = 2 # accepted
        invitation.save()
        conv.members.add(invitation.receiver)
        conv.save()
        itf = Interface(conv=conv, user=invitation.receiver)
        itf.save()

        member = invitation.receiver
        new_message = Message(content=f"欢迎新成员~~\n\n{member.name}成功加入了我们，让我们一起欢迎他 ^o^", type=0, sender=cur_user, conversation=conv)
        new_message.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            if member == cur_user:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'true'})
            else:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "invitation_message",
                    "conversationId": str(conv.id)
                }
            )
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "modify_members",
                    "conversationId": str(conv.id)
                }
            )
        
        return request_success({"message": "同意该用户入群"})

    elif req.method == "DELETE":
        invitation.status = 1 # rejected
        invitation.save()
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            str(member.id),
            {
                "type": "invitation_message",
                "conversationId": str(conv.id)
            }
        )
        return request_success({"message": "拒绝该用户入群"})

@CheckRequire
def conv_manage_notifications(req: HttpRequest):
    if req.method not in ["GET", "POST", "DELETE"]:
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if not jwt_token:
        return request_failed(-2, "Invalid or expired JWT", 401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    cur_user = User.objects.filter(id=payload["id"]).first()

    if req.method == "GET":
        conversation_id = req.GET.get("conversation_id", "")
        conv = Conversation.objects.filter(id=conversation_id).first()
        if not conv:
            return request_failed(-1, "Conversation not found", 404)
        notifications = Notification.objects.filter(conversation=conv).order_by("-time")
        if not notifications.exists():
            return_data = []
        else:
            return_data = []
            for notif in notifications:
                return_data.append({
                    "notification_id": notif.id,
                    "content": notif.content,
                    "sender_name": notif.sender.name,
                    "timestamp": float2time(notif.time),
                })
        return request_success({"notifications": return_data})
    elif req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        conversation_id = require(body, "conversation_id", "int", err_msg="Missing or error type of [conversation_id]")
        content = require(body, "content", "string", err_msg="Missing or error type of [content]")
        conv = Conversation.objects.filter(id=conversation_id).first()

        is_creator = (conv.creator.id == cur_user.id)
        is_admin = conv.managers.filter(id=cur_user.id).exists()
        if not is_creator and not is_admin:
            return request_failed(-3, "非群主或管理员不能发布公告", 403)
        
        notif = Notification(sender=cur_user, conversation=conv, content=content)
        notif.save()

        new_message = Message(content=f"[群公告]\n\n{content}", type=0, sender=cur_user, conversation=conv)
        new_message.save()
        channel_layer = get_channel_layer()
        for member in conv.members.all():# conv的所有member
            itf = Interface.objects.filter(conv=conv, user=member).first()
            itf.unreads += 1
            itf.last_message_id = new_message.id
            itf.save()
            if member == cur_user:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'true'})
            else:
                async_to_sync(channel_layer.group_send)(str(member.id), {'type': 'notify', 'scroll': 'false'})
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "notification_message",
                    "conversationId": str(conv.id)
                }
            )
        return request_success({"message": "发布群公告成功"})
    elif req.method == "DELETE":
        body = json.loads(req.body.decode("utf-8"))
        notification_id = require(body, "notification_id", "int", err_msg="Missing or error type of [notification_id]")
        notif = Notification.objects.filter(id=notification_id).first()
        if not notif:
            return request_failed(-1, "Notification not found", 404)
        is_creator = (notif.conversation.creator.id == cur_user.id)
        is_admin = notif.conversation.managers.filter(id=cur_user.id).exists()
        if not is_creator and not is_admin:
            return request_failed(-3, "非群主或管理员不能删除公告", 403)
        notif.delete()

        conv = Conversation.objects.filter(id=notif.conversation.id).first()
        channel_layer = get_channel_layer()
        for member in conv.members.all():
            async_to_sync(channel_layer.group_send)(
                str(member.id),
                {
                    "type": "notification_message",
                    "conversationId": str(conv.id)
                }
            )
        return request_success({"message": "删除群公告成功"})

@CheckRequire
def interface(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()

    if req.method == "GET":
        conversation_id = req.GET.get("conversationId", "")
        conver = Conversation.objects.filter(id=conversation_id).first()
        if not conver:
            return request_failed(-1, "会话不存在", 404)
        itf = Interface.objects.filter(conv=conver, user=cur_user).first()
        if not itf:
            return request_failed(-1, "权限异常", 404)
        return_data = {
            "unreads": itf.unreads,
            "notification": itf.notification,
            "ontop": itf.ontop
        }
        return request_success(return_data)
    elif req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        conversation_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversation_id]")
        # conditional
        conver = Conversation.objects.filter(id=conversation_id).first()
        if not conver:
            return request_failed(-1, "会话不存在", 404)
        itf = Interface.objects.filter(conv=conver, user=cur_user).first()
        if not itf:
            return request_failed(-1, "权限异常", 404)
        if 'ontop' in body.keys():
            ontop = require(body, "ontop", "bool", err_msg="Missing or error type of [ontop]")
            itf.ontop = ontop
        if 'notification' in body.keys():
            notification = require(body, "notification", "bool", err_msg="Missing or error type of [notification]")
            itf.notification = notification
        if 'unreads' in body.keys():
            unreads = require(body, "unreads", "bool", err_msg="Missing or error type of [unreads]")
            if unreads == True:
                itf.unreads = 1
        itf.save()
        return request_success()
    else:
        return BAD_METHOD

# @CheckRequire
# def upload_image(request: HttpRequest):
#     print(Image.objects.all())
#     if request.method == 'POST':
#         print("in post !!!!!")
#         if 'image' in request.FILES:
#             file = request.FILES['image']
#             image = Image(image=file)
#             image.save()
#             print(Image.objects.all())
#             return request_success({"message": "添加图片成功"})
#         else:
#             return request_failed(-1, "未成功上传图片", 404)
#     if request.method == 'GET':
#         print("in get !!!!")
#         image = Image.objects.all().first()
#         if image:
#             image_url = request.build_absolute_uri(image.image.url)
#             return request_success({"url": image_url})
#         else:
#             return request_failed(-1, "图片未找到", 404)
#     return request_failed(-1, "方法不是POST或者GET", 404)

@CheckRequire
def read_list(req: HttpRequest): #已读列表
    if req.method != "POST":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()
    body = json.loads(req.body.decode("utf-8"))
    message_id = require(body, "message_id", "int", err_msg="Missing or error type of [message_id]")
    message = Message.objects.filter(id=message_id).first()
    if not message:
        return request_failed(-1, "消息不存在", 404)
    if message.conversation.members.filter(id=cur_user.id).first() == None:
        return request_failed(-3, "权限异常", 400)
    users = [
        {
            "avatar": user.avatar,
            # "avatar": True if user.avatar else False,
            "name": user.name
        }
        for user in message.read_by.all()
    ]
    return request_success({"read_users": users})

@CheckRequire
def sift_messages(req: HttpRequest): #筛选消息
    if req.method != "POST":
        return BAD_METHOD
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    cur_user = User.objects.filter(id=payload["id"]).first()

    body = json.loads(req.body.decode("utf-8"))

    conversation_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversationId]")
    conv = Conversation.objects.filter(id=conversation_id).first()
    if not conv:
        return request_failed(-1, "会话不存在", 404)
    if conv.members.filter(id=cur_user.id).first() == None:
        return request_failed(-3, "权限异常", 400)
    
    queryset = Message.objects.filter(conversation=conv).exclude(invisible_to=cur_user)
    if "start_time" in body:
        start_time = require(body, "start_time", "string", err_msg="Missing or error type of [start_time]")
        start_time = time2float(start_time)
        queryset = queryset.filter(time__gte=start_time)
    if "end_time" in body:
        end_time = require(body, "end_time", "string", err_msg="Missing or error type of [end_time]")
        end_time = time2float(end_time)
        queryset = queryset.filter(time__lte=end_time)
    if "sender_id" in body:
        sender_id = require(body, "sender_id", "int", err_msg="Missing or error type of [sender_id]")
        queryset = queryset.filter(sender__id=sender_id)
    if "content" in body:
        content = require(body, "content", "string", err_msg="Missing or error type of [content]")
        queryset = queryset.filter(content__contains=content)    
        
    queryset = queryset.order_by('time')

    messages_serialize = [
        {
            "id": _message_.id,
            "type": _message_.type,
            "sender_id": _message_.sender.id,
            "sender_name": _message_.sender.name,
            "sender_avatar": _message_.sender.avatar,
            # "sender_avatar": True if _message_.sender.avatar else False,
            "content": _message_.content,
            "timestamp": float2time(_message_.time)
        }
        for _message_ in queryset
    ]
    return request_success({"messages": messages_serialize})