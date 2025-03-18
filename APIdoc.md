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
- password: 用户密码，应当为非空字符串，由字母、数字、下划线组成，且长度不大于20

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
- 如果用户恢复，状态码200，返回信息"已恢复账户，请用原密码登录"。

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
    "name": "user_name",
    "password": "********"
}
```

- name: 用户昵称
- password: 用户密码

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
- 若用户已注销，状态码404，错误码1，错误信息"User deleted"。 
- 若密码错误，状态码401，错误码-3，错误信息"密码错误"。 

#### 个人信息管理/account/info

该API用于获取或修改用户的个人信息。

##### 获取个人信息

GET请求：

```json
{
    "email": "user_email"
}
```

- email: 用户的唯一身份标识，为邮箱

请求成功时，设置状态码为200OK，返回用户的个人信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "Succeed",
    "name": "userName",
    "email": "userEmail",
    "user_info":"user_info",
    "avatar_path": "userAvatarUrl",
    "deleted": false // 是否已被注销
}
```

name: 用户昵称

- email: 用户邮箱
- user_info: 用户信息
- avatar_path: 用户头像URL
- deleted: 该用户是否已被注销

请求失败时，错误响应格式为：

```json
{  
    "code": *, 
    "info": "[error message]"
}
```

- 若用户邮箱不存在，状态码404，错误码-1，错误信息"用户不存在"。 

##### 修改个人信息

PUT请求：

```json
{
    "name": "newUserName",
    "email": "newUserEmail",
    "user_info": "newUserInfo",
    "avatar_path": "newUserAvatarUrl"
}
```

- name: 用户昵称
- email: 用户邮箱
- user_info: 用户信息
- avatar_path: 用户头像URL

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"Invalid or expired JWT"。 
- 若用户邮箱格式错误，状态码400，错误码1，错误信息"Invalid email"。 
- 若用户昵称不符合要求，状态码400，错误码-3，错误信息"Name too long"。

### 好友关系

#### 用户查找/search_user

该API用于查找指定ID的用户。

通过GET方式请求，请求体为：

```json
{
    "query": "targetId"
}
```

- query: 要查找的用户的ID

响应：  
请求成功时，设置状态码为200OK，返回查找用户的基本信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "id": "userId",
    "name": "userName",
    "email": "userEmail",
    "avatar_path": "userAvatarUrl",
    "deleted": false // 是否已被注销
}
```

- id: 用户ID
- name: 用户昵称
- email: 用户邮箱
- avatar_path: 用户头像URL
- deleted: 该用户是否已被注销

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若查找的用户id错误或不存在或者已经被注销，状态码404，错误码-1，错误信息"所查找用户不存在"。  

#### 好友申请/add_friend

该API用于向指定用户发送好友申请。

通过POST方式请求，请求体为：

```json
{
    "userId": "userId",
    "searchId": "targetId",
    "message":"Hello"
}
```

- userId: 发送好友申请的用户ID
- searchId: 要查找的用户的ID
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若查找的用户id错误或不存在或者已经被注销，状态码404，错误码-1，错误信息"所查找用户不存在"。  
- 若用户已是好友，状态码403，错误码-4，错误信息"您已是该用户的好友"。  
- 若用户已发送过好友申请，状态码403，错误码-5，错误信息"您已发送过好友申请"。  
- 若用户试图添加自己为好友，状态码403，错误码-6，错误信息"您不能添加自己为好友"。 

#### 好友申请列表/friend_requests

该API用于查看指定用户的好友申请列表。

通过GET方式请求，请求体为：

```json
{
    "userId": "userId"
}
```

- userId: 查看好友申请的用户ID

响应：  
请求成功时，设置状态码为200OK，返回好友申请列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "requests": [
        {
            "user_id": "UserId",
            "user_name": "UserName",
            "avatar_path": "AvatarUrl",
            "message": "申请消息",
            "deleted": false, // 是否已被注销
            "timestamp": "2025-03-13T14:30:00Z" ,// 申请时间
            "status": 0 // 0: 等待处理，1: 已同意，2: 已拒绝
        },
        {
            "user_id": "UserId",
            "user_name": "UserName",
            "avatar_path": "AvatarUrl",
            "message": "申请消息",
            "deleted": false, // 是否已被注销
            "timestamp": "2025-03-13T14:30:00Z" ,// 申请时间
            "status": 1 // 0: 等待处理，1: 已同意，2: 已拒绝
        }
    ]
}
```

- requests: 好友申请列表，包含申请者的ID、昵称、头像URL、申请消息、状态。
- user_id: 申请者ID
- user_name: 申请者昵称
- avatar_path: 申请者头像URL
- message: 申请消息
- deleted: 该用户是否已被注销
- timestamp: 申请时间
- status: 申请状态，0: 等待处理，1: 已同意，2: 已拒绝

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。        

#### 处理好友申请/friend_requests/{requestId}

该API用于处理（同意或拒绝）指定好友申请。允许POST和DELETE请求。

通过POST方式请求，请求体为：

```json
{
    "send_user_id": "userId",
    "accept_user_id": "targetId"
}
```

响应：  
请求成功时，设置状态码为200OK，返回拒绝好友申请成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "已接受好友申请"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。
- 若处理的用户已经被注销，状态码404，错误码-1，错误信息"用户已注销"。    

DELETE请求：

```json
{
    "send_user_id": "userId",
    "reject_user_id": "targetId"
}
```

响应：  
请求成功时，设置状态码为200OK，返回删除好友申请成功的消息，成功响应格式为:

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。
- 若处理的用户已经被注销，状态码404，错误码-1，错误信息"用户已注销"。

#### 分组管理/groups

该API用于管理用户的分组，包括获取和创建分组，允许GET和POST请求。  

##### 获取分组名单

GET请求：

```json
{
    "userId": "userId"
}
```

- userId: 查看分组名单的用户ID

响应：  
请求成功时，设置状态码为200OK，返回分组名单，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "groups": [
        {
            "id": "groupId",
            "name": "groupName"
        },
        {
            "id": "groupId",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 

##### 创建分组

POST请求：

```json
{
    "userId": "userId",
    "name": "groupName"
}
```

- userId: 创建分组的用户ID
- name: 分组名称

响应：  
请求成功时，设置状态码为200OK，返回创建分组成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "创建分组成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组名称已存在，状态码409，错误码-1，错误信息"分组名称已存在"。 

#### 分组操作/groups/{groupId}

该API用于操作指定分组，包括查看分组详情、修改分组名称、删除分组。

##### 查看分组详情

GET请求：

```json
{
    "userId": "userId",
    "groupId": "groupId"
}
```

- userId: 查看分组详情的用户ID
- groupId: 查看分组详情的分组ID

响应：  
请求成功时，设置状态码为200OK，返回分组详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "group": {
        "id": "groupId",
        "name": "groupName",
    }
}
```

- group: 分组详情，包含分组的ID、名称、成员列表。
- id: 分组ID
- name: 分组名称

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 

##### 修改分组名称

PUT请求：

```json
{
    "userId": "userId",
    "groupId": "groupId",
    "name": "newGroupName"
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 
- 若分组名称已存在，状态码409，错误码-1，错误信息"分组名称已存在"。 

##### 删除分组

DELETE请求：

```json
{
    "userId": "userId",
    "groupId": "groupId"
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 

#### 组内成员管理/groups/{groupId}/members

该API用于管理指定分组的成员，包括获取分组成员列表、添加分组成员、删除分组成员。

##### 获取分组成员列表

GET请求：

```json
{
    "groupId": "groupId"
}
```

- groupId: 获取分组成员列表的分组ID

响应：  
请求成功时，设置状态码为200OK，返回分组成员列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "members": [
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl",
        },  
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl",
        }
    ]
}
```

- members: 分组成员列表，包含成员的ID、昵称、头像URL。
- id: 成员ID
- name: 成员昵称
- avatar_path: 成员头像URL

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 

##### 添加分组成员

POST请求：

```json
{
    "userId": "userId",
    "groupId": "groupId",
    "memberId": "targetId"
}
```

- userId: 添加分组成员的用户ID
- groupId: 添加分组成员的分组ID
- memberId: 要添加的成员ID

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 
- 若成员不存在，状态码404，错误码-1，错误信息"成员不存在"。 
- 若成员已在分组中，状态码403，错误码-3，错误信息"成员已在分组中"。 

##### 删除分组成员

DELETE请求：

```json
{
    "userId": "userId",
    "groupId": "groupId",
    "memberId": "targetId"
}
```

- userId: 删除分组成员的用户ID
- groupId: 删除分组成员的分组ID
- memberId: 要删除的成员ID

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 
- 若成员不存在，状态码404，错误码-1，错误信息"成员不存在"。 
- 若成员不在分组中，状态码403，错误码-3，错误信息"成员不在分组中"。         

#### 好友列表/friends

该API用于查看指定用户的好友列表。

通过GET方式请求，请求体为：

```json
{
    "userId": "userId"
}
```

- userId: 查看好友列表的用户ID

响应：  
请求成功时，设置状态码为200OK，返回好友列表，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "friends": [
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl",
        },  
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl",
        }
    ]
}
```

- friends: 好友列表，包含好友的ID、昵称、头像URL。
- id: 好友ID
- name: 好友昵称
- avatar_path: 好友头像URL

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若用户不存在，状态码404，错误码-1，错误信息"用户不存在"。 

#### 好友操作/friends/{friendId}

该API用于操作指定好友，包括查看好友详情、删除好友，为好友分组操作。

##### 查看好友详情

GET请求：

```json
{
    "userId": "userId",
    "friendId": "friendId"
}
```

- userId: 查看好友详情的用户ID
- friendId: 查看好友详情的好友ID

响应：  
请求成功时，设置状态码为200OK，返回好友详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "id": "friendId",
    "name": "userName",
    "avatar_path": "AvatarUrl",
    "email": "userEmail",
    "phone": "userPhone",
    "deleted": false,
    "groups": "groupname"
}
```

- id: 好友ID
- name: 好友昵称
- avatar_path: 好友头像URL
- email: 好友邮箱
- phone: 好友手机号
- `deleted`: 好友是否已注销
- `groups`: 好友所在分组名称

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若用户不存在，状态码404，错误码-1，错误信息"用户不存在"。 
- 若好友不存在，状态码404，错误码-1，错误信息"好友不存在"。 

##### 删除好友

DELETE请求：

```json
{
    "userId": "userId",
    "friendId": "friendId"
}
```

- userId: 删除好友的用户ID
- friendId: 要删除的好友ID

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若用户不存在，状态码404，错误码-1，错误信息"用户不存在"。 
- 若好友不存在，状态码404，错误码-1，错误信息"好友不存在"。 

##### 好友分组操作

PUT请求：

```json
{
    "userId": "userId",
    "friendId": "friendId",
    "groupId": "groupId"
}
```

- userId: 操作好友的用户ID
- friendId: 操作的好友ID
- groupId: 要移动到的分组ID

响应：  
请求成功时，设置状态码为200OK，返回操作好友分组成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "操作好友分组成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若用户不存在，状态码404，错误码-1，错误信息"用户不存在"。 
- 若好友不存在，状态码404，错误码-1，错误信息"好友不存在"。 
- 若分组不存在，状态码404，错误码-1，错误信息"分组不存在"。 
- 若好友已经有分组，状态码403，错误码-3，错误信息"好友已经有分组"。 

### 在线会话

#### 获取聊天界面 /conversations

该 API 用于获取会话列表，创建会话。

##### 获取会话列表

GET请求：

```json
{
    "conversationId": "conversationId"
}
```

响应：
请求成功时，设置状态码为200OK，返回聊天界面的信息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "conversation": [
        {
            "id":"convid",
            "name":"conversationName",
            "avatar_path":"AvatarUrl",
            "last_message":"lastMessage",
            "last_message_time":"lastMessageTime",
            "is_chat_group":true,
            "is_top":true,
            "notice_able":true,
            "unread_count":0
        }
        {
            "id":"convid",
            "name":"conversationName",
            "avatar_path":"AvatarUrl",
            "last_message":"lastMessage",
            "last_message_time":"lastMessageTime",
            "is_chat_group":true,
            "is_top":true,
            "notice_able":true,
            "unread_count":0
        }
    ]
}
```

- conversation: 聊天列表，包含参与人头像、消息列表等。
- id: 会话ID
- name: 会话名称
- avatar_path: 参与人头像URL
- last_message: 最后一条消息内容
- last_message_time: 最后一条消息时间
- is_chat_group: 是否为群聊
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 

##### 创建会话

POST请求：

```json
{
    "userId": "userId",
    "members": ["userId1", "userId2"],
    "is_chat_group": true,
    "host_id": "userId",
    "name": "conversationName",
    "avatar_path": "AvatarUrl",
    "timestamp": "2025-03-13T14:30:00Z"
}
```

- userId: 创建会话的用户ID
- members: 会话参与人ID列表
- is_chat_group: 是否为群聊
- host_id: 会话创建者ID，默认为创建者id
- name: 会话名称
- avatar_path: 会话头像URL
- timestamp: 会话创建时间

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若成员不存在，状态码404，错误码-1，错误信息"成员不存在"。 

#### 聊天消息发送 /conversations/{conversationId}/messages

该API用于发送消息。  

POST请求：

```json
{
    "conversationId": "conversationId",
    "sender_id": "userId",
    "is_chat_group": true,
    "receiver_id": ["userId1", "userId2"],
    "content": "messageContent",
    "timestamp": "2025-03-13T14:30:00Z"
}
```

- conversationId: 发送消息的会话ID
- sender_id: 发送者ID
- is_chat_group: 是否为群聊
- receiver_id: 接收者ID列表
- content: 消息内容
- timestamp: 消息发送时间

响应：
请求成功时，设置状态码为200OK，返回发送消息成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 
- 若发送者不存在，状态码404，错误码-1，错误信息"发送者不存在"。 
- 若接收者不存在，状态码404，错误码-1，错误信息"接收者不存在"。 

#### 回复消息/conversations/{conversationId}/messages/{messageId}/reply

该API用于回复消息。

POST请求：

```json
{
    "conversationId": "conversationId",
    "message_id": "messageId",
    "sender_id": "userId",
    "content": "messageContent",
    "timestamp": "2025-03-13T14:30:00Z"
}
```

- conversationId: 回复消息的会话ID
- message_id: 回复的消息ID
- sender_id: 回复者ID
- content: 回复消息内容
- timestamp: 回复消息时间

响应：  
请求成功时，设置状态码为200OK，返回回复消息成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 
- 若消息不存在，状态码404，错误码-1，错误信息"消息不存在"。 
- 若发送者不存在，状态码404，错误码-1，错误信息"发送者不存在"。 

#### 会话管理 /conversations/{conversationId}

该API用于管理特定的会话，包括查看会话详情，聊天记录，置顶会话，免打扰会话

##### 查看会话详情

GET请求：

```json
{
    "conversationId": "conversationId",
}
```

- conversationId: 查看会话详情的会话ID

响应：
请求成功时，设置状态码为200OK，返回会话详情，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "id": "convid",
    "is_chat_group": true,
    "name": "conversationName",
    "avatar_path": "AvatarUrl",
    "last_message": "lastMessage",
    "last_message_time": "lastMessageTime",
    "is_top": true,
    "notice_able": true,
    "members": [
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl"
        },
        {
            "id": "userId",
            "name": "userName",
            "avatar_path": "AvatarUrl"
        }
    ],
    "notification":[
        {
            "id": "notificationId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "sender_avatar_path": "AvatarUrl",
            "content": "notificationContent",
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "id": "notificationId", 
            "sender_id": "senderId",
            "sender_name": "senderName",
            "sender_avatar_path": "AvatarUrl",
            "content": "notificationContent",
            "timestamp": "2025-03-13T14:30:00Z"
        }
    ] 
}
```

- id: 会话ID
- is_chat_group: 是否为群聊
- name: 会话名称
- avatar_path: 会话头像URL
- last_message: 最后一条消息内容
- last_message_time: 最后一条消息时间
- is_top: 是否置顶
- notice_able: 是否允许提醒
- members: 会话参与人列表，包含参与人ID、昵称、头像URL等。
- notification: 通知列表，包含通知ID、发送者ID、发送者昵称、发送者头像、通知内容、通知时间等。

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。     

##### 查看会话聊天记录

GET请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId"
}
```

- conversationId: 查看会话聊天记录的会话ID

响应：
请求成功时，设置状态码为200OK，返回会话聊天记录，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "messages": [
        {
            "id": "messageId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "is_self": true,
            "sender_avatar_path": "AvatarUrl",
            "content": "messageContent",
            "reply_num": 0,
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "id": "messageId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "is_self": false,
            "sender_avatar_path": "AvatarUrl",
            "content": "messageContent",
            "reply_num": 0,
            "timestamp": "2025-03-13T14:30:00Z"
        }
    ]
}
```

- messages: 会话消息列表，包含消息ID、发送者ID、发送者昵称、发送者头像、消息内容、消息时间等。
- id: 消息ID
- sender_id: 发送者ID
- sender_name: 发送者昵称
- is_self: 是否为自己发送的消息
- sender_avatar_path: 发送者头像URL
- content: 消息内容
- reply_num: 回复消息数
- timestamp: 消息时间

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 

##### 置顶会话

POST请求：

```json
{
    "conversationId": "conversationId",
    "is_top": true
}
```

- conversationId: 置顶会话的会话ID
- is_top: 是否置顶

响应：
请求成功时，设置状态码为200OK，返回置顶会话成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "置顶会话成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 

##### 免打扰会话

POST请求：

```json
{
    "conversationId": "conversationId",
    "notice_able": true
}
```

- conversationId: 免打扰会话的会话ID
- notice_able: 是否允许提醒

响应：
请求成功时，设置状态码为200OK，返回免打扰会话成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
    "message": "免打扰会话成功"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 

#### 聊天记录管理 /conversations/{conversationId}/messages

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
            "sender_avatar_path": "AvatarUrl",
            "content": "messageContent",
            "timestamp": "2025-03-13T14:30:00Z"
        },
        {
            "id": "messageId",
            "sender_id": "senderId",
            "sender_name": "senderName",
            "sender_avatar_path": "AvatarUrl",
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
- sender_avatar_path: 发送者头像URL
- content: 消息内容
- timestamp: 消息时间

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 

##### 删除聊天记录

DELETE请求：

```json
{
    "conversationId": "conversationId",
    "message_id": "messageId"
}
```

- conversationId: 删除聊天记录的会话ID
- message_id: 要删除的消息ID

响应：
请求成功时，设置状态码为200OK，返回删除聊天记录成功的消息，成功响应格式为:

```json
{
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若会话不存在，状态码404，错误码-1，错误信息"会话不存在"。 
- 若消息不存在，状态码404，错误码-1，错误信息"消息不存在"。 

### 群聊管理

#### 设置群组管理员/conversations/{conversationId}/set_admin

该API用于设置群组管理员。

POST请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "admin_id": "adminId"
}
```

- conversationId: 设置群组管理员的会话ID
- userId: 设置管理员的用户ID
- admin_id: 需要添加的管理员ID

响应：
请求成功时，设置状态码为200OK，返回设置群组管理员成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 权限不足，状态码403，错误码-3，错误信息"非群主不能设置管理员"。  
- 若设置的成员已经是管理员，状态码403，错误码-3，错误信息"成员已经是管理员"。 

#### 解除群组管理员/conversations/{conversationId}/unset_admin

该API用于解除群组管理员。

DELETE请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "admin_id": "adminId"
}
```

- conversationId: 解除群组管理员的会话ID
- userId: 解除管理员的用户ID
- admin_id: 需要解除的管理员ID

响应：
请求成功时，设置状态码为200OK，返回解除群组管理员成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 权限不足，状态码403，错误码-3，错误信息"非群主不能解除管理员"。  
- 若解除的管理员不是群组管理员，状态码403，错误码-3，错误信息"管理员不是群组管理员"。 

#### 发布群公告/conversations/{conversationId}/notifications

该API用于发布群公告。

POST请求：

```json
{
    "conversationId": "conversationId",
    "sender_id": "userId",
    "content": "content",
    "timestamp": "2025-03-13T14:30:00Z"
}
```

- conversationId: 发布群公告的会话ID
- sender_id: 发布公告的用户ID
- content: 公告内容
- timestamp: 公告发布时间

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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若发布公告的非群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能发布公告"。 

#### 群主转让/conversations/{conversationId}/transfer_owner

该API用于群主转让。

POST请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "new_owner_id": "newOwnerId"
}
```

- conversationId: 群主转让的会话ID
- userId: 转让群主的用户ID
- new_owner_id: 转让群主的新群主ID

响应：
请求成功时，设置状态码为200OK，返回群主转让成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若转让群主的非群主，状态码403，错误码-3，错误信息"非群主不能转让群主"。 
- 若转让的新群主不是群组成员，状态码403，错误码-3，错误信息"新群主不是群组成员"。 

#### 移除群成员/conversations/{conversationId}/remove_member

该API用于移除群成员。

DELETE请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "member_id": "memberId"
}
```

- conversationId: 移除群成员的会话ID
- userId: 移除群成员的用户ID
- member_id: 要移除的群成员ID

响应：
请求成功时，设置状态码为200OK，返回移除群成员成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若移除普通群员的非群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能移除群员"。 
- 若移除群管理员的非群主，状态码403，错误码-3，错误信息"非群主不能移除群管理员"。 
- 若移除的群成员不是群组成员，状态码403，错误码-3，错误信息"群成员不是群组成员"。 

#### 退出群组/conversations/{conversationId}/quit

该API用于退出群组。

DELETE请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId"
}
```

- conversationId: 退出群组的会话ID
- userId: 退出群组的用户ID

响应：
请求成功时，设置状态码为200OK，返回退出群组成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若退出群组的非群成员，状态码403，错误码-3，错误信息"非群成员不能退出群组"。       

#### 进群邀请/conversations/{conversationId}/invite

该API用于群组邀请。

POST请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "member_id": ["memberId1", "memberId2"],
    "timestamp": "2025-03-13T14:30:00Z"
}
```

- conversationId: 群组邀请的会话ID
- userId: 群组邀请的用户ID
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

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若邀请的成员已经是群组成员，状态码403，错误码-3，错误信息"成员已经是群组成员"。 

#### 处理群组邀请/conversations/{conversationId}/handle_invite

该API用于处理群组邀请。

POST请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "invite_id": "inviteId",
    "memberid": "memberId",
    "timestamp": "2025-03-13T14:30:00Z",
    "status": "true"
}
```

- conversationId: 处理群组邀请的会话ID
- userId: 处理群组邀请的用户ID
- invite_id: 发出邀请的成员ID
- memberid: 处理群组邀请的成员ID
- timestamp: 发出邀请的时间
- status: 处理结果，true为接受邀请，false为拒绝邀请

响应：
请求成功时，设置状态码为200OK，返回处理群组邀请成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success",
    "message": "同意该用户入群"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若非群主或管理员处理群组邀请，状态码403，错误码-3，错误信息"非群主或管理员不能处理邀请"。 

#### 更新群信息/conversations/{conversationId}/update_info

该API用于更新群信息。

POST请求：

```json
{
    "conversationId": "conversationId",
    "userId": "userId",
    "name": "groupName",
    "avatar_path": "AvatarUrl",
    "admins": ["adminId1", "adminId2"],
    "members": ["memberId1", "memberId2"]
}
```

- conversationId: 更新群信息的会话ID
- userId: 更新群信息的用户ID
- name: 群名称  
- avatar_path: 群头像URL
- admins: 群管理员ID列表
- members: 群成员ID列表

响应：
请求成功时，设置状态码为200OK，返回更新群信息成功的消息，成功响应格式为:

```json
{    
    "code": 0,
    "info": "success"
}
```

请求失败时，错误相应的格式为：

```json
{  
    "code": *,  
    "info": "[error message]"
}
```

- 若JWT令牌错误或过期，状态码401，错误码-2，错误信息"登录已失效"。 
- 若更新群信息的非群主或管理员，状态码403，错误码-3，错误信息"非群主或管理员不能更新群信息"。 
