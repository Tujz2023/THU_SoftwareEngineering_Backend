import json
from utils.utils_jwt import check_jwt_token
from channels.generic.websocket import AsyncWebsocketConsumer
import logging

logger = logging.getLogger("ims_consumer")
logger.setLevel(logging.INFO)

if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

class IMSConsumer(AsyncWebsocketConsumer):
    # 当客户端尝试建立 WebSocket 连接时调用
    async def connect(self) -> None:
        # 从查询字符串中提取用户名
        # self.userid: str = self.scope['query_string'].decode('utf-8').split('=')[1]
        jwt_token = self.scope['query_string'].decode('utf-8').split('=')
        jwt_token = '='.join(jwt_token[1:])
        payload = check_jwt_token(jwt_token)
        self.userid = str(payload["id"])

        # 将当前 WebSocket 连接添加到一个全体用户组中
        # 这样可以确保发给这个组的所有消息都会被转发给目前连接的所有客户端
        await self.channel_layer.group_add(self.userid, self.channel_name)

        # 接受 WebSocket 连接
        await self.accept()

    # 当 WebSocket 连接关闭时调用
    async def disconnect(self, close_code: int) -> None:
        # 将当前 WebSocket 从其所在的组中移除
        await self.channel_layer.group_discard(self.userid, self.channel_name)

    # 向指定用户组发送 notification
    async def notify(self, event) -> None:
        logger.info(f"发送[notify]消息")
        await self.send(text_data=json.dumps({'type': 'notify'}))

    async def request_message(self, event):# 好友请求
        logger.info(f"发送[request_message]消息")
        await self.send(
            text_data=json.dumps(
                {
                    "type": "request_message",
                }
            )
        )
    
    async def delete_friend(self, event):# 好友删除
        logger.info(f"发送[delete_friend]消息")
        await self.send(
            text_data=json.dumps(
                {
                    "type": "delete_friend",
                }
            )
        )

    async def invitation_message(self, event):# 进群邀请
        await self.send(
            text_data=json.dumps(
                {
                    "type": "invitation_message",
                }
            )
        )

    async def notification_message(self, event): # 群聊通知
        await self.send(
            text_data=json.dumps(
                {
                    "type": "notification_message",
                }
            )
        )

    async def conv_setting(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "conv_setting",
                }
            )
        )
       