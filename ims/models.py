from utils import utils_time
from django.db import models
from utils.utils_request import return_field

from utils.utils_require import MAX_CHAR_LENGTH, MAX_AVATAR_LENGTH
from utils.utils_avatar import DEFAULT_AVATAR
from utils.utils_time import time2float, float2time

class User(models.Model):
    id = models.BigAutoField(primary_key=True, unique=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=MAX_CHAR_LENGTH)
    password = models.CharField(max_length=MAX_CHAR_LENGTH) # 加密后的密码
    created_time = models.FloatField(default=utils_time.get_timestamp)
    user_info = models.CharField(max_length=MAX_CHAR_LENGTH, default="该用户很懒，什么也没有留下~")
    # avatar = models.ImageField(upload_to='avatar/user/', blank=True, null=True)
    avatar = models.CharField(max_length=MAX_AVATAR_LENGTH, default=DEFAULT_AVATAR)
    deleted = models.BooleanField(default=False)
    
    class Meta:
        indexes = [models.Index(fields=["id"])]

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name, 
            "email": self.email, 
            "avatar": self.avatar,
            "user_info": self.user_info,
            "deleted": self.deleted
        }

    def conversations(self): # 返回conversation列表
        convs = Conversation.objects.filter(members=self)
        return {
            "email": self.email, 
            "name": self.name, 
            "conversations": [ return_field(conv.serialize(), ["id", "content", "sender", "conversation", "created_time"])
                       for conv in convs ]
        }
    
    def __str__(self) -> str:
        return self.id

class Conversation(models.Model):
    # types: 0-private, 1-group
    type = models.IntegerField(default=0)
    id = models.BigAutoField(primary_key=True, unique=True)
    members = models.ManyToManyField(User)
    ConvName = models.CharField(max_length=MAX_CHAR_LENGTH, default="群组")
    created_time = models.FloatField(default=utils_time.get_timestamp)
    avatar = models.CharField(max_length=MAX_AVATAR_LENGTH)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, null=True, related_name="creator")
    managers = models.ManyToManyField(User, related_name="managers")
    last_message_id = models.IntegerField(default=-1)
    
    class Meta:
        indexes = [models.Index(fields=["id"])]

    def serialize(self):
        return {
            "id": self.id,
            "name": self.ConvName,
            "type": self.type,
            "avatar": self.avatar if type == 1 else "",
            "creator": self.creator.id,
            "last_message_id": self.last_message_id,
        }

    def __str__(self) -> str:
        return f"conversation {self.id}"

class Interface(models.Model):
    id = models.BigAutoField(primary_key=True, unique=True)
    conv = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    notification = models.BooleanField(default=True)
    unreads = models.IntegerField(default=0)
    ontop = models.BooleanField(default=False)

    class Meta:
        indexes = [models.Index(fields=["id"])]

    def serialize(self):
        return {
            "id": self.id,
            "user": self.user.id,
            "notification": self.notification,
            "unreads": self.unreads,
            "ontop": self.ontop
        }
    def __str__(self) -> str:
        return f"interface {self.id} of user {self.user.id} in conversation {self.conv.id}"

class Message(models.Model):
    id = models.BigAutoField(primary_key=True, unique=True)
    content = models.TextField() # 是否加密传输
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    time = models.FloatField(default=utils_time.get_timestamp)
    visible_to = models.ManyToManyField(User, related_name="visible_to")

    class Meta:
        indexes = [models.Index(fields=["id", "time"])]

    def serialize(self):
        return {
            "id": self.id,
            "content": self.content,
            "senderid": self.sender.id,
            "sendername": self.sender.name,
            # "senderavatar": self.sender.avatar,
            "senderavatar": "true" if self.sender.avatar else "false",
            "conversation": self.conversation.id,
            "created_time": float2time(self.time)
        }
    
    def __str__(self) -> str:
        return f"message {self.id}"

class Request(models.Model):
    id = models.BigAutoField(primary_key=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="request_sender")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="request_receiver")
    message = models.CharField(
        max_length=255,
        blank=True,
    )
    time = models.FloatField(default=utils_time.get_timestamp)
    status = models.IntegerField(default=0) # 0-waiting, 1-accepted, 2-rejected, 3-already friends

    class Meta:
        indexes = [models.Index(fields=["id"])]
    def __str__(self) -> str:
        return f"request from {self.sender.id} to {self.receiver.id}"

class Invitation(models.Model):
    id = models.BigAutoField(primary_key=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="invitation_sender")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="invitation_receiver")
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    time = models.FloatField(default=utils_time.get_timestamp)
    status = models.IntegerField(default=0) # 0-waiting, 1-rejected, 2-accepted

    class Meta:
        indexes = [models.Index(fields=["id"])]
    def __str__(self) -> str:
        return f"invitation from {self.sender.id} to {self.receiver.id} for conversation {self.conversation.id}"
    
class Group(models.Model):
    id = models.BigAutoField(primary_key=True, unique=True)
    name = models.CharField(max_length=MAX_CHAR_LENGTH)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_groups")
    members = models.ManyToManyField(User, related_name="friend_groups", blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["id", "name"]),
            models.Index(fields=["owner"]),
        ]

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner.id,
            "members": [member.id for member in self.members.all()],
        }

    def __str__(self):
        return f"Group {self.name} (ID: {self.id}) - Owner: {self.owner.id}"
    
class Notification(models.Model):
    id = models.BigAutoField(primary_key=True, unique=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notification_sender")
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    content = models.TextField()
    time = models.FloatField(default=utils_time.get_timestamp)

    class Meta:
        indexes = [models.Index(fields=["id", "time"])]

    def serialize(self):
        return {
            "id": self.id,
            "sender": self.sender.id,
            "conversation": self.conversation.id,
            "content": self.content,
            "created_time": self.time
        }

    def __str__(self) -> str:
        return f"notification {self.id} from {self.sender.id} in conversation {self.conversation.id}"