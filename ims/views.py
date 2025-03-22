import json
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.core.files.uploadedfile import SimpleUploadedFile

from ims.models import User
from ims.models import Conversation, User, Message, Request, Invitation, Group, Interface
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

@CheckRequire 
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
            if user.password != password:
                return request_failed(-3, "Wrong password", 401)
            user.deleted = False
            user.save()
            return request_success({"message": "已恢复账户"})
        return request_failed(-1, "User already exists", 400)
    else:
        user = User(email=email, name=name, password=password)
        user.save()
        return_data = {
            "token": generate_jwt_token(email),
            "message": "注册成功"
        }
        return request_success(return_data)

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
    user = User.objects.filter(email=payload["email"]).first()
    user.deleted = True
    user.save()
    return request_success({"message": "注销成功"})

@CheckRequire 
def account_info(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(2, "Invalid or expired JWT", status_code=401) 
    user = User.objects.filter(email=payload["email"]).first()
    # if jwt is valid, user must exist
    if req.method == "GET":
        # body = json.loads(req.body.decode("utf-8"))
        # email = require(body, "email", "string", err_msg="Missing or error type of [email]")
        # email = req.GET.get("email")
        # email = require({"email": email}, "email", "string", err_msg="Missing or error type of [email]")
        return_data = {
            "email": user.email,
            "name": user.name,
            "user_info": user.user_info,
            "avatar_path": user.avatar.url if user.avatar else "",
            "deleted": user.deleted,
        }
        return request_success(return_data)
    elif req.method == "PUT":
        invalid_email = False
        invalid_name = False

        body = json.loads(req.body.decode("utf-8"))
        newname = require(body, "name", "string", err_msg="Missing or error type of [name]")
        if len(newname) > 20 or newname == "":
            invalid_name = True
        else:
            user.name = newname
        newemail = require(body, "email", "string", err_msg="Missing or error type of [email]")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", newemail):
            invalid_email = True
        else:
            user.email = newemail
        user.user_info = require(body, "user_info", "string", err_msg="Missing or error type of [user_info]")
        _avatar_path = require(body, "avatar_path", "string", err_msg="Missing or error type of [avatar_path]")
        user.avatar = SimpleUploadedFile(name=str(user.id), content=open(_avatar_path, 'rb').read(), content_type='image/jpeg')
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
    
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)

    if req.method != "GET":
        return BAD_METHOD
    

    query_name = req.GET.get("query_name", "")

    # 执行查询
    users = User.objects.filter(name = query_name, deleted=False)  # 只查询未注销用户

    if not users.exist():
        return request_failed(-1, "User not found or deleted", 404)
    
    result=[
        {
            "user_id": user.id,
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
    
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    if req.method != "POST":
        return BAD_METHOD
    
    body = json.loads(req.body.decode("utf-8"))

    user_email = payload["email"]
    target_id = require(body, "target_id", "int", err_msg="Missing or error type of [target_id]")
    message = require(body, "message", "string", err_msg="Missing or error type of [message]")

    user_cur = User.objects.filter(email=user_email).first()

    # 验证被添加用户是否存在
    user = User.objects.filter(id=target_id).first()
    if not user:
        return request_failed(1, "User not found", 404)
    
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
    
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    
    if req.method != "GET":
        return BAD_METHOD
    
    user_email = payload["email"]

    cur_user_id = User.objects.filter(email=user_email).first().id

    friend_requests = Request.objects.filter(receiver__email=user_email).order_by("-time")  # 按申请时间降序排列

    # 构造返回的请求列表
    request_list = [
        {
            "sender_user_id": req.sender.id,
            "receiver_user_id": cur_user_id,
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

    if not receiver:
        return request_failed(-1, "User deleted", 404)

    if req.method == "POST":
        # 处理好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()
        request.status = 2
        request.save()

        new_conversation = Conversation(type=0)
        new_conversation.save()
        new_conversation.members.add(sender, receiver)

        return request_success({"message": "已接受好友申请"})

    elif req.method == "DELETE":
        # 拒绝好友请求
        request = Request.objects.filter(sender=sender, receiver=receiver).first()

        request.status = 1
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
        user_email = payload["email"]
        groups = Group.objects.filter(owner__email=user_email)
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
        user_email = payload["email"]
        body = json.loads(req.body.decode("utf-8"))
        name = require(body, "name", "string", err_msg="Missing or error type of [name]")

        existing_group = Group.objects.filter(owner__email=user_email, name=name).first()
        if existing_group:
            return request_failed(-1, "Group already exists", 400)
        
        new_group = Group.objects.create(owner_id=user_email, name=name)
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
                "avatar_path": member.avatar.url if member.avatar else "",
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
        user_email = payload["email"]
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
        user_email = payload["email"]
        body = json.loads(req.body.decode("utf-8"))
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")

        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-1, "Group not found", 404)
        
        group.delete()


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
                "avatar_path": member.avatar.url if member.avatar else "",
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
            return request_failed(-1, "Group not found", 404)
        
        member = User.objects.filter(id=member_id).first()
        if not member:
            return request_failed(-1, "Member not found", 404)
        
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
            return request_failed(-1, "Group not found", 404)
        
        member = User.objects.filter(id=member_id).first()
        if not member:
            return request_failed(-1, "Member not found", 404)
        
        if not group.members.filter(id=member_id).exists():
            return request_failed(-3, "Member not in group", 400)
        
        group.members.remove(member)



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
    
    user_email = payload["email"]

    # 从对话中获取好友列表中好友的email列表
    friends_emails = (
        Conversation.objects.filter(type=0).filter(members__email=user_email)
        .values_list("members__email", flat=True)
        .exclude(members__email=user_email)  # 排除自己
        .distinct()  # 避免重复 
    )

    friends = User.objects.filter(email__in=friends_emails)

    friends_list = [
        {
            "id": friend.id,
            "email": friend.email,
            "name": friend.name,
            "avatar_path": friend.avatar.url if friend.avatar else "",
        }
        for friend in friends
    ]

    return request_success({"friends": friends_list})

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
        user_email = payload["email"]
        friend_id = req.GET.get("friend_id", "")

        user = User.objects.filter(email=user_email).first()
        if not user:
            return request_failed(-1, "User not found", 404)
        
        friend = User.objects.filter(id=friend_id).first()
        if not friend:
            return request_failed(-1, "Friend not found", 404)
        
        friend_groups = Group.objects.filter(members=friend)
        
        return_data = {
            "id": friend.id,
            "email": friend.email,
            "name": friend.name,
            "avatar_path": friend.avatar.url if friend.avatar else "",
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
    elif req.method == "DELETE":
        body = json.loads(req.body.decode("utf-8"))
        user_email = payload["email"]
        friend_id = require(body, "friend_id", "int", err_msg="Missing or error type of [friend_id]")

        user = User.objects.filter(email=user_email).first()
        if not user:
            return request_failed(-1, "User not found", 404)
        
        friend = User.objects.filter(id=friend_id).first()
        if not friend:
            return request_failed(-1, "Friend not found", 404)
        
        Conversation.objects.filter(type=0).filter(members=user).filter(members=friend).delete()

        # 删除好友之间的请求
        Request.objects.filter(sender=user, receiver=friend).delete()
        Request.objects.filter(sender=friend, receiver=user).delete()

        return request_success({"message": "删除好友成功"})
    
    # 好友分组操作
    elif req.method == "PUT":
        body = json.loads(req.body.decode("utf-8"))
        user_email = payload["email"]
        friend_id = require(body, "friend_id", "int", err_msg="Missing or error type of [friend_id]")
        group_id = require(body, "group_id", "int", err_msg="Missing or error type of [group_id]")

        user = User.objects.filter(email=user_email).first()
        if not user:
            return request_failed(-1, "User not found", 404)
        
        friend = User.objects.filter(id=friend_id).first()
        if not friend:
            return request_failed(-1, "Friend not found", 404)
        
        group = Group.objects.filter(id=group_id).first()
        if not group:
            return request_failed(-1, "Group not found", 404)
        
        if group.members.filter(id = friend.id).exists():   
            return request_failed(-3, "Friend already in group", 400)
        
        group.members.add(friend)

        return request_success({"message": "添加好友到分组成功"})
        
@CheckRequire
def conv(req: HttpRequest):
    if req.method not in ["GET", "POST"]:
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401) 
    cur_user = User.objects.filter(email=payload["email"]).first()

    if req.method == "GET":
        body = json.loads(req.body.decode("utf-8"))
        conv_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversation_id]")
        conv = Conversation.objects.filter(id=conv_id).first()
        if not conv:
            return request_failed(-1, "Conversation not found", 404)
        return request_success({"conversation": conv.serialize()})
    elif req.method == "POST":
        body = json.loads(req.body.decode("utf-8"))
        members = require(body, "members", "list", err_msg="Missing or error type of [members]")
        new_conv = Conversation(type=1,)
        for member in members:
            if not User.objects.filter(email=member).exists():
                return request_failed(-1, "User not found", 404)
            member_user = User.objects.filter(email=member).first()
            if not Conversation.objects.filter(
            type=0  # 私聊类型
            ).filter(members=member_user).filter(members=cur_user).exists():
                return request_failed(-3, "Not friend with current user.", 400)
            new_conv.members.add(member_user)
        new_conv.save()
        return request_success({"conversation": new_conv.serialize()})


@CheckRequire
def message(req: HttpRequest):
    if req.method not in ["POST", "GET"]:
        return BAD_METHOD
    # jwt check
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401) 
    # cur_user = User.objects.filter(email=payload["email"]).first()
    # if cur_user not in Conversation.objects.filter(id=conv_id).first().members.all():
    #     return request_failed(1, "Not in conversation", 400)
    body = json.loads(req.body.decode("utf-8"))
    conv_id = require(body, "conversationId", "int", err_msg="Missing or error type of [conversation_id]")
    conv = Conversation.objects.filter(id=conv_id).first()
    cur_user = User.objects.filter(email=payload["email"]).first()
    if cur_user not in Conversation.objects.filter(id=conv_id).first().members.all():
        return request_failed(1, "Not in conversation", 400)
    if not conv:
        return request_failed(-1, "Conversation not found", 404)

    if req.method == "POST":
        content = require(body, "content", "string", err_msg="Missing or error type of [content]")
        if content == "":
            return request_failed(-3, "Content is empty", 400)
        if len(content) > MAX_CHAR_LENGTH:
            return request_failed(-3, "Content is too long", 400)
        new_message = Message(content=content, sender=cur_user, conversation=conv)
        new_message.save()
        return request_success()
    else:
        # GET method
        messages = Message.objects.filter(conversation=conv).order_by("time")
        return request_success({"messages": [msg.serialize() for msg in messages]})

@CheckRequire 
def interface(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    if jwt_token == None or jwt_token == "":
        return request_failed(-2, "Invalid or expired JWT", status_code=401)
    payload = check_jwt_token(jwt_token)
    if payload is None:
        return request_failed(-2, "Invalid or expired JWT", status_code=401) 
    cur_user = User.objects.filter(email=payload["email"]).first()

    conversation_id = req.GET.get("conversation_id", "")
    conver = Conversation.objects.filter(id=conversation_id).first()
    if not conver:
        return request_failed(-1, "Conversation not found", 404)
    itf = Interface.objects.filter(conv=conver, user=cur_user).first()
    if not itf:
        return request_failed(-1, "Conversation does not contain user", 404)
    if req.method == "GET":
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
        if 'ontop' in body.keys():
            ontop = require(body, "ontop", "bool", err_msg="Missing or error type of [ontop]")
            itf.ontop = ontop
        if 'notification' in body.keys():
            notification = require(body, "notification", "bool", err_msg="Missing or error type of [notification]")
            itf.notification = notification
        if 'unreads' in body.keys():
            unreads = require(body, "unreads", "int", err_msg="Missing or error type of [unreads]")
            itf.unreads = unreads
        itf.save()
        return request_success()
    else:
        return BAD_METHOD
    