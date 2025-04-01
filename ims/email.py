from datetime import datetime, timedelta
from django.utils.html import strip_tags
class verification_email:
    def __init__(self, code: str):
        self.subject = "即时通讯系统 - 验证码"
        self.message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Instant Messages验证码邮件</title>
            </head>
            <body>
                <p>您好！</p>
                <p>欢迎使用即时通讯系统。您的验证码是：<strong>{ code }</strong></p>
                <p>此验证码将在 5 分钟后过期。</p>
                <p>谢谢！</p>
            </body>
            </html>"""
        self.plain_message = strip_tags(self.message)
