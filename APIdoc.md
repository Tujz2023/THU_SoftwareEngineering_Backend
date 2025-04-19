# IMS API文档

**eyJhbGci组**

除用户登录和注册时其他请求API时需要携带 JWT 令牌验证身份。请求头需要将 Authorization 字段设置为 JWT 令牌。

### 基本管理

#### 用户注册/account/reg

该API用于用户注册。

POST请求

```json
{
    "email": "user@example.com",
    "password": "********",
    "name": "username",
}
```

- name: 用户昵称，应当为非空字符串，可以包含任何utf-8字符，且长度不大于20
- password: 加密之后的用户密码，解密后应当为非空字符串，由字母、数字、下划线组成，且长度不大于20

请求成功时，设置状态码为200OK，返回用户的基本信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "token": "JWTtoken",
    "message": "注册成功"
}
```

请求失败时，错误响应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若用户昵称不符合要求，状态码400，错误码-3，错误信息"Name too long"。
- 若用户已存在，状态码400，错误码-1，错误信息"User already exists"。
- 若用户密码不符合要求，状态码400，错误码-4，错误信息"Password illegal"。
- 如果用户恢复，状态码200，返回信息"已恢复账户"，并携带JWTtoken。

#### 用户注销/account/delete

该API用于用户注销。

DELETE请求

没有请求体。请求头带有JWT令牌。

- 请求成功时，设置状态码为200OK，返回注销成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "message": "注销成功"
}
```

请求失败时，错误响应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。

### 用户认证

#### 用户登录/account/login

该API用于用户登录。

POST请求

```json
{
    "email": "user@example.com",
    "password": "********"
}
```

- name: 用户昵称
- password: 加密之后的用户密码

请求成功时，设置状态码为200OK，返回JWT令牌，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "token": "***.***.***" // JWT令牌
}
```

请求失败时，错误响应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若用户不存在，状态码404，错误码-1，错误信息"User not found"。
- 若用户已注销，状态码404，错误码1，错误信息"User deleted or not activated"。
- 若密码错误，状态码401，错误码-3，错误信息"密码错误"。

#### 获取验证码/verify

该API用于向邮箱发送验证码。

POST请求：

```json
{
    "email": "user@example.com"
}
```

请求成功时，设置状态码为200OK，返回加密后的验证码，成功相应格式为：

```json
{
    "code": 0,
    "info": "Succeed",
    "verify_code": "******",
    "message": "发送成功"
}
```

- verify_code: 加密后的验证码

请求失败时，错误相应格式为：

```json
{
    "code": *,
    "info": "[error message]"
}
```

- 若发送失败，状态码404，错误码-5，错误信息"发送失败，请检查网络和邮箱"。
- 若用户邮箱格式错误，状态码400，错误码1，错误信息"Invalid email"。

#### 个人信息管理/account/info

该API用于获取或修改用户的个人信息。

##### 获取个人信息

GET请求：

使用authorization头部携带JWT令牌。
无请求体

请求成功时，设置状态码为200OK，返回用户的个人信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "name": "userName",
    "email": "userEmail",
    "user_info":"user_info",
    "avatar": "userAvatar",
    "deleted": false, // 是否已被注销
    "id": id
}
```

name: 用户昵称

- email: 用户邮箱
- user_info: 用户信息
- avatar: 用户头像base64码
- deleted: 该用户是否已被注销
- id: 该用户的id

请求失败时，错误响应格式为：

```json
{  
    "code": *, 
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。

##### 修改个人信息

PUT请求：

```json
{
    "origin_password": "origin_password",
    "name": "newUserName",
    "password": "newpassword",
    "email": "newUserEmail",
    "user_info": "newUserInfo",
    "avatar": "newUserAvatar"
}
```

- origin_password: 加密之后的用户输入的原密码
- name: 用户昵称
- password: 加密之后的用户密码
- email: 用户邮箱
- user_info: 用户信息
- avatar: 用户头像base64码

请求成功时，设置状态码为200OK，返回修改成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "message": "修改成功"
}
```

请求失败时，错误响应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若用户输入的原密码无法匹配，状态码401，错误码-3，错误信息"密码错误"。
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若用户邮箱格式错误，状态码400，错误码1，错误信息"Invalid email"。
- 若用户昵称不符合要求，状态码400，错误码-3，错误信息"Name too long"。
- 若用户密码不符合要求，状态码400，错误码-4，错误信息"Invalid password"

### 好友关系

#### 用户查找/search_user

该API用于查找指定昵称的用户。

请求头需要带有JWT令牌。

通过GET方式请求，请求携带参数为：

```json
{
    "query_name": "target_name"
}
```

- query_name: 要查找的用户的昵称

响应：
请求成功时，设置状态码为200OK，返回查找用户的基本信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "results": [
        {
            "user_id": user_id,
            "name": "userName",
            "email": "userEmail",
            "avatar": "userAvatarUrl",
            "is_friend": True,  
            "deleted": True
        },
        {
            "user_id": user_id,
            "name": "userName",
            "email": "userEmail",
            "avatar": "userAvatarUrl",
            "is_friend": False,
            "deleted": False
        }
    ]
}
```

- name: 用户昵称
- user_id: 用户ID
- email: 用户邮箱
- avatar: 用户头像URL
- is_friend: 该用户是否是好友
- deleted: 该用户是否已被注销

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若无查询条件，状态码400，错误码-7，错误信息"Missing or error type of [query_name]"。
- 若查找的结果不存在，返回success，状态码200，以及空列表

#### 好友申请/add_friend

该API用于向指定用户发送好友申请。

请求头中需要包含代表当前用户的JWT令牌。

通过POST方式请求，请求体为：

```json
{
    "target_id": target_id,
    "message":"Hello",
}
```

- target_id: 接收好友申请的用户ID
- message: 申请消息

响应：
请求成功时，设置状态码为200OK，返回申请成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "申请成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若目标用户或不存在或者已经被注销或当前用户不存在，状态码404，错误码-1，错误信息"User not found or deleted"。
- 若用户已是好友，状态码403，错误码-4，错误信息"Already friends"。
- 若已经向对方发送过好友请求但是对方并未处理，状态码403，错误码-5，错误信息"Friend request already sent"。
- 若向自己发送好友请求，状态码403，错误码-6，错误信息"Can not add yourself as friend"。

#### 好友申请列表/friend_requests

该API用于查看指定用户的好友申请列表。

通过GET方式请求，请求体为：

使用authorization头部携带JWT令牌。

无请求体

响应：
请求成功时，设置状态码为200OK，返回好友申请列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "requests": [
        {
            "sender_user_id": user_id,
            "receiver_user_id": user_id,
            "user_email": "user_email",
            "user_name": "UserName",
            "avatar": "AvatarUrl",
            "message": "申请消息",
            "created_at": "2025-03-13T14:30:00Z", // 申请时间
            "status": 0 // 0: 等待处理，1: 已同意，2: 已拒绝，3：已成为好友
        },
        {
            "sender_user_id": user_id,
            "receiver_user_id": user_id,
            "user_email": "user_email",
            "user_name": "UserName",
            "avatar": "AvatarUrl",
            "message": "申请消息",
            "created_at": "2025-03-13T14:30:00Z", // 申请时间
            "status": 1 // 0: 等待处理，1: 已同意，2: 已拒绝，3：已成为好友
        }
    ]
}
```

- requests: 好友申请列表，包含申请者的ID、昵称、头像URL、申请消息、状态。
- sender_user_id: 申请者ID
- receiver_user_id: 接收者ID
- user_email: 申请者邮箱
- user_name: 申请者昵称
- avatar: 申请者头像URL
- message: 申请消息
- created_at: 申请时间
- status: 申请状态，0: 等待处理，1: 已同意，2: 已拒绝，3：已成为好友(不是通过自己同意加的好友)

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若不存在好友申请，返回success，状态码200，以及空列表。

#### 处理好友申请/friend_request_handle

该API用于处理（同意或拒绝）指定好友申请。允许POST和DELETE请求。

通过POST方式请求，请求体为：

```json
{
    "sender_user_id": sender_id,
    "receiver_user_id": receiver_id
}
```

- send_user_id: 发送好友申请的用户ID
- receiver_user_id: 接收好友申请的用户ID

响应：
请求成功时，设置状态码为200OK，返回接收好友申请成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "已接受该好友申请"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若处理的用户或发送消息的用户已经被注销，状态码404，错误码-1，错误信息"User deleted"。
- 若该好友申请不存在，状态码403，错误码-5，错误信息"Request not found"。
- 若用户已是好友，状态码403，错误码-4，错误信息"Already friends"。

DELETE请求：

```json
{
    "sender_user_id": sender_id,
    "receiver_user_id": receiver_id
}
```

响应：
请求成功时，设置状态码为200OK，返回拒绝好友申请成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "已拒绝该好友申请"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若处理的用户或发送消息的用户已经被注销，状态码404，错误码-1，错误信息"User deleted"。
- 若该好友申请不存在，状态码403，错误码-5，错误信息"Request not found"。
- 若用户已是好友，状态码403，错误码-4，错误信息"Already friends"。

#### 分组管理/groups

该API用于管理用户的分组，包括获取和创建分组，允许GET和POST请求。

##### 获取分组名单

GET请求：

使用authorization头部携带JWT令牌。
无请求体

响应：
请求成功时，设置状态码为200OK，返回分组名单，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "groups": [
        {
            "id": group_id,
            "name": "groupName"
        },
        {
            "id": group_id,
            "name": "groupName"
        }
    ]
}
```

- groups: 分组列表，包含分组的ID和名称。
- id: 分组ID
- name: 分组名称

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若无分组，返回success，状态码200，以及空列表。

##### 创建分组

POST请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "name": "groupName"
}
```

- name: 分组名称

响应：
请求成功时，设置状态码为200OK，返回创建分组成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "分组创建成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组名称已存在，状态码409，错误码-1，错误信息"Group already exists"。

#### 分组操作/groups/manage_groups

该API用于操作指定分组，包括查看分组详情、修改分组名称、删除分组。

##### 查看分组详情

GET请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "group_id": "group_id"
}
```

- group_id: 查看分组详情的分组ID

响应：
请求成功时，设置状态码为200OK，返回分组详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "group": {
        "id": group_id,
        "name": "groupName",
        "members": [
            {
                "id": user_id,
                "email": "user_email",
                "name": "userName",
                "avatar": "AvatarUrl",
                "deleted": True
            },  
            {
                "id": user_id,
                "email": "user_email",
                "name": "userName",
                "avatar": "AvatarUrl",
                "deleted": False
            }
        ]
    }
}
```

- group: 分组详情，包含分组的ID、名称、成员列表。
- id: 分组ID
- name: 分组名称
- members: 分组成员列表，包含成员的id、email、昵称、头像URL。
- id：成员ID
- email: 成员邮箱
- name: 成员昵称
- avatar: 成员头像URL
- deleted: 成员账号是否注销

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-1，错误信息"Group not found"。

##### 修改分组名称

PUT请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "group_id": group_id,
    "new_name": "newGroupName"
}
```

响应：
请求成功时，设置状态码为200OK，返回修改分组名称成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "修改分组名称成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-1，错误信息"Group not found"。
- 若分组名称已存在，状态码409，错误码-1，错误信息"Name already exists"。

##### 删除分组

DELETE请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "group_id": group_id
}
```

响应：
请求成功时，设置状态码为200OK，返回删除分组成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "删除分组成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-1，错误信息"Group not found"。

#### 组内成员管理/groups/members

该API用于管理指定分组的成员，包括获取分组成员列表、添加分组成员、删除分组成员。

##### 获取分组成员列表

GET请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "group_id": "group_id"
}
```

- group_id: 获取分组成员列表的分组ID

响应：
请求成功时，设置状态码为200OK，返回分组成员列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "members": [
        {
            "id": user_id,
            "email": "user_email",
            "name": "userName",
            "avatar": "AvatarUrl",
            "deleted": True
        },  
        {
            "id": user_id,
            "email": "user_email",
            "name": "userName",
            "avatar": "AvatarUrl",
            "deleted": False
        }
    ]
}
```

- members: 分组成员列表，包含成员的id、email、昵称、头像URL。
- id: 成员ID
- email: 成员邮箱
- name: 成员昵称
- avatar: 成员头像URL
- deleted: 成员是否注销

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-1，错误信息"Group not found"。

##### 添加分组成员

POST请求：

```json
{
    "group_id": group_id,
    "member_id": target_id
}
```

- group_id: 添加分组成员的分组ID
- member_id: 要添加的成员ID

响应：
请求成功时，设置状态码为200OK，返回添加分组成员成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "添加分组成员成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-3，错误信息"Group not found"。
- 若成员不是自己的好友，状态码404，错误码-1，错误信息"Member is not friend"。
- 若成员已在分组中，状态码400，错误码-3，错误信息"Member already in group"。

##### 删除分组成员

DELETE请求：

```json
{
    "group_id": group_id,
    "member_id": target_id
}
```

- group_id: 删除分组成员的分组ID
- member_id: 要删除的成员ID

响应：
请求成功时，设置状态码为200OK，返回删除分组成员成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "删除分组成员成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若分组不存在，状态码404，错误码-3，错误信息"Group not found"。
- 若成员不在分组中，状态码400，错误码-3，错误信息"Member not in group"。

#### 好友列表/friends

该API用于查看指定用户的好友列表。

需要使用authorization头部携带JWT令牌。

无请求体

响应：
请求成功时，设置状态码为200OK，返回好友列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "friends": [
        {
            "id": user_id,
            "email": "user_email",
            "name": "userName",
            "avatar": "AvatarUrl",
            "deleted": True
        },  
        {
            "id": user_id,
            "email": "user_email",
            "name": "userName",
            "avatar": "AvatarUrl",
            "deleted": False
        }
    ]
}
```

- friends: 好友列表，包含好友的id、email、昵称、头像URL。
- id: 好友ID
- email: 好友邮箱
- name: 好友昵称
- avatar: 好友头像URL
- deleted: 好友是否注销

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若好友不存在，返回success，状态码200，以及空列表

#### 好友操作/manage_friends

该API用于操作指定好友，包括查看好友详情、删除好友，为好友分组操作。

##### 查看好友详情

GET请求：

需要使用authorization头部携带JWT令牌。

请求体为：

```json
{
    "friend_id": "friend_id"
}
```

- friend_id: 查看好友详情的好友ID

响应：
请求成功时，设置状态码为200OK，返回好友详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "id": user_id,
    "email": "friend_email",
    "name": "userName",
    "avatar": "AvatarUrl",
    "user_info":"user_info",
    "deleted": false,
    "groups": [
        {
            "id": group_id,
            "name": "groupName"
        },
        {
            "id": group_id,
            "name": "groupName"
        }
    ]
}
```

- id: 好友ID
- email: 好友邮箱
- name: 好友昵称
- avatar: 好友头像URL
- user_info: 用户信息
- deleted: 好友是否已注销
- groups: 好友所在分组名称

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若用户不存在，状态码404，错误码-1，错误信息"User not found"。
- 若好友不存在，状态码404，错误码-1，错误信息"Friend not found"。

##### 删除好友

DELETE请求：

需要使用authorization头部携带JWT令牌。
请求体为：

```json
{
    "friend_id": friend_id
}
```

- friend_id: 删除的好友ID

响应：
请求成功时，设置状态码为200OK，返回删除好友成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "删除好友成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若好友不存在，状态码404，错误码-1，错误信息"Friend not found"。
- 若对方已经不是好友，状态码404，错误码-3，错误信息"Already not friend"。

#### 查询单独用户信息/search_user_detail

该 API 用于获取单独用户的信息

GET请求：

需要使用authorization头部携带JWT令牌。

请求体：

```json
{
    "userId": userId
}

响应：
请求成功时，设置状态码为200OK，返回该用户的相关信息，成功相应格式为：

```json
{
    "code": 0,
    "info": "success",
    "user": {
        "name": "name",
        "email": "example@email.com",
        "avatar": "avatar",
        "is_friend": False
    }
}
```

- name: 该用户的昵称
- email: 该用户的邮箱
- avatar: 该用户的头像
- is_friend: 该用户是否为自己的好友

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若用户不存在，状态码404，错误码-1，错误信息"User not found"。

### 在线会话

#### 获取聊天界面 /conversations

该 API 用于获取会话列表，创建会话。

##### 获取会话列表

GET请求：

需要使用authorization头部携带JWT令牌。
无请求体

响应：
请求成功时，设置状态码为200OK，返回聊天列表及每个聊天的相关信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "conversation": [
        {
            "id": convid,
            "name":"conversationName",
            "avatar":"AvatarUrl",
            "last_message":"lastMessage",
            "last_message_time":"lastMessageTime",
            "is_chat_group":true,
            "is_top":true,
            "notice_able":true,
            "unread_count":0
        },
        {
            "id":convid,
            "name":"conversationName",
            "avatar":"AvatarUrl",
            "last_message":"lastMessage",
            "last_message_time":"lastMessageTime",
            "is_chat_group":false,
            "friend_id":friendid,
            "is_top":true,
            "notice_able":true,
            "unread_count":0
        },
        ...
    ]
}
```

- conversation: 聊天列表，包含参与人头像、消息列表等。
- id: 会话ID
- name: 会话名称
- avatar: 参与人头像URL
- last_message: 最后一条消息内容
- last_message_time: 最后一条消息时间
- is_chat_group: 是否为群聊
- friendid: 若是私聊，则返回好友的id(群聊时无这个字段)
- is_top: 是否置顶
- notice_able: 是否允许提醒
- unread_count: 未读消息数

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话列表为空，返回正常，状态码200，会话列表为空列表。

##### 创建会话

POST请求：

```json
{
    "members": [user1.id, user2.id],
    "name": "conversationName"
}
```

- members: 会话参与人ID列表，不包括创建者自己
- name: 会话名称

响应：
请求成功时，设置状态码为200OK，返回创建会话成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "创建会话成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若有一个成员不是自己的好友，状态码400，错误码-3，错误信息"Not friend with current user."。
- 若成员不存在，状态码404，错误码-1，错误信息"成员不存在"。

#### 聊天消息发送 /conversations/messages

该API用于发送和接收消息列表。

##### 获取消息列表

GET请求：

需要使用authorization头部携带JWT令牌。

```json
{
    "conversationId": "conversationId",
    "from": "2025-03-13T14:30:00Z"
}
```

其中from为起始的消息时间，如果没有该字段，则默认从头。
from的格式为"%Y-%m-%d %H:%M:%S"，例如"2023-04-01 12:30:45"

响应：
请求成功时，设置状态码为200OK，该群聊中的所有聊天记录，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "messages": [
        {
            "id": id,
            "type": 1,
            "content": "image.url",
            "senderid": senderId,
            "sendername": "name",
            "senderavatar": "avatar",
            "reply_to": "reply content",
            "reply_to_id": replyId,
            "conversation": conversationId,
            "created_time": "2025-03-13T14:30:00Z"
        },
        {
            "id": id,
            "type": 0,
            "content": "content",
            "senderid": senderId,
            "sendername": "name",
            "senderavatar": "avatar",
            "conversation": conversationId,
            "created_time": "2025-03-13T14:30:20Z"
        },
        ...
    ]
}
```

- id: 消息的id
- type: 消息的类型，0为普通消息，1为图片
- content: 消息的内容，若type=1的时候，为图片的url
- senderid: 消息发送者的id
- sendername: 消息发送者的昵称
- senderavatar: 消息发送者的头像
- reply_to: 回复消息的内容
- reply_to_id: 回复消息的id
- conversation: 群聊id
- created_time: 消息发送时间

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。
- 若用户不在会话中，状态码400，错误码1，错误信息"用户不在会话中"。
- 若群聊内没有消息，返回正常，状态码200，messages为空列表。
- 若没有回复的消息，则不存在reply_to和reply_to_id字段。

POST请求(只用于发送普通类型的消息)：

```json
{
    "conversationId": "conversationId",
    "content": "messageContent",
    "reply_to": reply_to_id
}
```

- conversationId: 发送消息的会话ID
- content: 消息内容
- reply_to: 回复消息的id(为可选项)

响应：
请求成功时，设置状态码为200OK，返回发送消息成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若当前用户并没有在会话中，状态码400，错误码1，错误信息“Not in conversation”。
- 若会话不存在，状态码404，错误码-1，错误信息"Conversation not found"。
- 若消息为空，状态码400，错误码-3，错误信息"Content is empty"。
- 若消息过长（>255），状态码400，错误码-3，错误信息"Content too long"。
- 若回复的消息不存在或者不在该会话中，状态码400，错误码-4，错误信息"Reply message not found"。

#### 聊天消息发送 /conversations/image

该API用于发送和接收消息列表。

POST请求(只用于发送图片，并且图片信息不可以用来回复其他消息)：

需要使用authorization头部携带JWT令牌。

使用formdata把图片传过来，具体地：
```json
{
    "conversationId": "conversationId",
    "image": image
}
```

- conversationId字段: 发送消息的会话ID
- image字段: 图片

响应：
请求成功时，设置状态码为200OK，返回发送消息成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若当前用户并没有在会话中，状态码400，错误码1，错误信息“Not in conversation”。
- 若会话不存在，状态码404，错误码-1，错误信息"Conversation not found"。

#### 查看回复列表 /conversations/get_reply

该API用于查看回复列表。  

GET请求：

```json
{
    "message_id": message_id,
}
```

- message_id: 查看回复列表的消息ID

响应：
请求成功时，设置状态码为200OK，返回回复列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "replies": [
        {
            "reply_id": reply_id,
            "sender_id": sender_id,
            "sender_name": "sender_name",
            "sender_avatar": "AvatarUrl",
            "content": "replyContent",
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "reply_id": reply_id,
            "sender_id": sender_id,
            "sender_name": "sender_name",
            "sender_avatar": "AvatarUrl",
            "content": "replyContent",
            "timestamp": "2025-03-13T14:30:00Z"
        }
    ]
}
```

- replies: 回复列表，包含回复ID、发送者ID、发送者昵称、发送者头像、回复内容、回复时间等。
- reply_id: 回复ID
- sender_id: 发送者ID
- sender_name: 发送者昵称
- sender_avatar: 发送者头像URL
- content: 回复内容
- timestamp: 回复时间

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若消息不存在，状态码404，错误码-1，错误信息"Message not found"。

#### 会话管理 /interface

该API用于管理特定的会话，包括查看会话详情，聊天记录，置顶会话，免打扰会话

##### 查看会话详情

GET请求：

```json
{
    "conversation_id": cid,
}
```

- conversation_id: 查看会话详情的会话ID

响应：
请求成功时，设置状态码为200OK，返回会话详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "unreads": itf.unreads,
    "notification": itf.notification,
    "ontop": itf.ontop
}
```

- ontop: 是否置顶
- notification: 是否允许提醒
- unreads: 未读消息数

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。
- 若会话权限异常，状态码403，错误码-3，错误信息"权限异常"。

##### 置顶会话、消息免打扰、未读信息数设置 /interface

POST请求：

```json
{
    "conversationId": "conversationId",
    "ontop": true,
    "notification": false,
    "unreads": "unread_number"
}
```

- conversationId: 置顶会话的会话ID
- ontop: 是否置顶，默认保持
- notification: 是否消息免打扰，默认保持
- unreads: 未读消息数，默认为保持

响应：
请求成功时，设置状态码为200OK，返回置顶会话成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。
- 若会话权限异常，状态码403，错误码-3，错误信息"权限异常"。

#### 聊天记录管理 /conversations/manage_messages

该API用于管理特定会话的聊天记录，包括筛选聊天记录，删除聊天记录

##### 筛选聊天记录

GET请求：

```json
{
    "conversationId": "conversationId",
    "start_time": "2025-03-13T14:30:00Z",
    "end_time": "2025-03-13T14:30:00Z",
    "sender_id": "senderId",
    "sender_name": "senderName",
    "content": "messageContent" 
}
```

- conversationId: 筛选聊天记录的会话ID
- start_time: 筛选开始时间
- end_time: 筛选结束时间
- sender_id: 发送者ID
- sender_name: 发送者昵称
- content: 消息内容

响应：
请求成功时，设置状态码为200OK，返回筛选后的聊天记录，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "messages": [
        {
            "id": "messageId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "sender_avatar": "AvatarUrl",
            "content": "messageContent",
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "id": "messageId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "sender_avatar": "AvatarUrl",
            "content": "messageContent",
            "timestamp": "2025-03-13T14:30:00Z"
        }
    ]
}
```

- messages: 筛选后的聊天记录列表，包含消息ID、发送者ID、发送者昵称、发送者头像、消息内容、消息时间等。
- id: 消息ID
- sender_id: 发送者ID
- sender_name: 发送者昵称
- sender_avatar: 发送者头像URL
- content: 消息内容
- timestamp: 消息时间

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。

##### 彻底删除聊天记录 /conversations/messages

注意：此操作从数据库中彻底删除某条聊天记录，对会话中所有用户有效。

DELETE请求：

```json
{
    "message_id": "messageId"
}
```

- message_id: 要删除的消息ID

响应：
请求成功时，设置状态码为200OK，返回删除聊天记录成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "message": "删除聊天记录成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若消息不存在，状态码404，错误码-1，错误信息"消息不存在"。
- 若不是消息发送者或不是群组管理员、群主，则无权限，状态码403，错误码-3，错误信息"No permission to delete message"。

### 群聊管理

#### 设置/解除群组管理员 /conversations/manage/admin

该API用于设置或解除群组管理员。

POST请求：

```json
{
    "conversation_id": conversationId,
    "user": uid,
}
```

- conversation_id: 设置群组管理员的会话ID
- user: 管理员的用户id

响应：
请求成功时，设置状态码为200OK，返回设置群组管理员成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "设置群组管理员成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。
- 若要设置的user不存在，状态码404，错误码-1，错误信息"User not found"。
- 若要设置的user不在群聊中，状态码400，错误码1，"User not in conversation"
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 权限不足，状态码403，错误码-3，错误信息"非群主不能设置管理员"。
- 若设置的成员已经是管理员，状态码403，错误码3，错误信息"成员已经是管理员"

DELETE请求：请求体与POST方法相同。

响应：
请求成功时，设置状态码为200OK，返回解除群组管理员成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "解除群组管理员成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若解除的管理员不是群组管理员，状态码403，错误码3，错误信息"管理员不是群组管理员"。
- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。
- 若要设置的user不存在，状态码404，错误码-1，错误信息"User not found"。
- 若要设置的user不在群聊中，状态码400，错误码1，"User not in conversation"
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 权限不足，状态码403，错误码-3，错误信息"非群主不能设置管理员"。

#### 查看、发布及删除群公告/conversations/manage/notifications

该API用于查看、发布和删除群公告。

GET请求：

```json
{
    "conversation_id": conversation_id,
}
```

- conversation_id: 查看群公告的会话ID

响应：
请求成功时，设置状态码为200OK，返回群公告内容，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "notifications": [
        {
            "notification_id": notification_id,
            "content": "公告内容",
            "sender_name": "senderName",
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "notification_id": notification_id,
            "content": "公告内容",
            "sender_name": "senderName",
            "timestamp": "2025-03-13T14:30:00Z"
        }
    ]
}
```

请求失败时，错误相应的格式为：  

```json
{  
    "code": *,  
    "info": "[error message]"
}
```
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。


POST请求：

```json
{
    "conversation_id": conversationId,
    "content": "content",
}
```

- conversation_id: 发布群公告的会话ID
- content: 公告内容

响应：
请求成功时，设置状态码为200OK，返回发布群公告成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "success",
    "message": "发布群公告成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若发布公告的非群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能发布公告"。

DELETE请求：

```json
{
    "notification_id": notification_id,
}
```

- notification_id: 要删除的公告ID

响应：
请求成功时，设置状态码为200OK，返回删除群公告成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "删除群公告成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若要删除的公告不存在，状态码404，错误码-1，错误信息"Notification not found"。
- 若要删除的公告不是群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能删除公告"。


#### 群主转让/conversations/manage/ownership_transfer

该API用于群主转让。

POST请求：

```json
{
    "conversation_id": conversationId,
    "user": uid,
}
```

- conversation_id: 设置群组管理员的会话ID
- user: 用户id

响应：
请求成功时，设置状态码为200OK，返回群主转让成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "群主转让成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若转让群主的非群主，状态码403，错误码-3，错误信息"非群主不能转让群主"。
- 若群主转让给自己，状态码403，错误码-3，错误信息"不能转让给自己"。
- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。
- 若要设置的user不存在，状态码404，错误码-1，错误信息"User not found"。
- 若要设置的user不在群聊中，状态码400，错误码1，"User not in conversation"
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。

#### 退出群组或移除群成员 /conversations/member/remove

POST请求：

该API用于退出群组。若群主退出则解散群聊。

```json
{
    "conversation_id": conversationId,
}
```

conversation_id: 所在会话ID

响应：
请求成功时，设置状态码为200OK，返回移除群成员成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "退出群组成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若要自身不在群聊中，状态码400，错误码1，"你不在群组中，无法退出"
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。

DELETE请求：

该API用于移除群成员。群主可以移除任意成员；管理员可以移除群主和管理员外的其他成员。

```json
{
    "conversation_id": conversationId,
    "user": uid,
}
```

- conversation_id: 所在会话ID
- user: 要移除的用户id

响应：
请求成功时，设置状态码为200OK，返回移除群成员成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message": "移除群成员成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 权限不足，状态码403，错误码-3，错误信息"非群主或管理员不能移除群成员"或"非群主不能移除管理员"。
- 若移除的群成员不是群组成员，状态码403，错误码-3，错误信息"群成员不是群组成员"。
- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。
- 若要设置的user不存在，状态码404，错误码-1，错误信息"User not found"。
- 若要设置的user不在群聊中，状态码400，错误码1，"User not in conversation"
- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。

#### 进群邀请/conversations/member/add

该API用于群组邀请。

POST请求：

```json
{
    "conversationId": conversationId,
    "member_id": member_id,
}
```

- conversationId: 群组邀请的会话ID
- member_id: 群组邀请的成员ID列表
- timestamp: 群组邀请时间

响应：
请求成功时，设置状态码为200OK，返回群组邀请成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "success",
    "message": "邀请成功，等待管理员确认"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若邀请的成员已经是群组成员，状态码403，错误码-3，错误信息"The member is already in the conversation"。
- 若邀请的成员不是自己的好友，状态码403，错误码-4，错误信息"The user is not your friend"。

#### 获取群组邀请/conversations/<conversation_id>/invitation

该API用于获取群组邀请列表。

GET请求：

无请求体

响应：
请求成功时，设置状态码为200OK，返回群组邀请列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "invitation": [
        {
            "invite_id": inviteId,
            "conversation_id": conversationId,
            "sender_id": senderId,
            "sender_name": "senderName",
            "receiver_id": receiverId,
            "receiver_name": "receiverName",
            "timestamp": "2025-03-13T14:30:00Z",
            "status": 0
        },
        {
            "invite_id": inviteId,
            "conversation_id": conversationId,
            "sender_id": senderId,
            "sender_name": "senderName",
            "receiver_id": receiverId,
            "receiver_name": "receiverName",
            "timestamp": "2025-03-13T14:30:00Z",
            "status": 1
        }
    ]
}
```

- invitation: 群组邀请列表，包含邀请ID、发起者ID、发起者昵称、接收者ID、接收者昵称、邀请时间等。
- invite_id: 邀请ID
- sender_id: 发起者ID
- sender_name: 发起者昵称
- receiver_id: 接收者ID
- receiver_name: 接收者昵称
- timestamp: 邀请时间
  请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若会话不存在，状态码404，错误码-1，错误信息"Conversation not found"。

#### 处理入群邀请/conversations/manage/handle_invitation

该API用于同意进群邀请或者拒绝该邀请

```json
{
    "conversation_id": conversationId,
    "invite_id": inviteId,
    "status": 0
}
```

- conversation_id: 处理群组邀请的会话ID
- invite_id: 发出邀请的成员ID
- status: 处理群组邀请的状态，0表示同意，1表示拒绝，2表示成功

POST请求：
响应：
请求成功时，设置状态码为200OK，返回处理群组邀请成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "success",
    "message": "同意该用户入群"
}
```

DELETE请求：
响应：
请求成功时，设置状态码为200OK，返回处理群组邀请成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "success",
    "message": "拒绝该用户入群"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若非群主或管理员处理群组邀请，状态码403，错误码-3，错误信息"非群主或管理员不能处理邀请"。
- 若status不为0，则表示已经有人处理过该邀请，状态码403，错误码-4，错误信息"邀请已处理"。

#### 更新群信息/conversations/manage/info

该API用于更新群信息。

POST请求：

```json

{
    "conversation_id": cid,
    "name": "groupName",
    "avatar": "AvatarUrl",
}
```

- conversation_id: 更新群信息的会话ID
- name: 群名称(可选)
- avatar: 群头像URL(可选)

响应：
请求成功时，设置状态码为200OK，返回更新群信息成功的消息，成功响应格式为:

```json
{  
    "code": 0,
    "info": "Succeed",
    "message":"修改群信息成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。
- 若更新群信息的非群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能更新群信息"。
- 若conversation不存在，状态码404，错误码-1，错误信息"Conversation not found"。
