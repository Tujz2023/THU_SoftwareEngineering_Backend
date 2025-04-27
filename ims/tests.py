import random
from django.test import TestCase, Client
from ims.models import (
    Conversation,
    User,
    Message,
    Request,
    Invitation,
    Group,
    Interface,
    Notification
)
import datetime
import hashlib
import hmac
import time
import json
import base64

from utils.utils_jwt import EXPIRE_IN_SECONDS, SALT, b64url_encode
from utils.utils_crypto import encrypt_text, decrypt_text

from channels.testing import ChannelsLiveServerTestCase, WebsocketCommunicator
from backend.asgi import application
from asgiref.sync import sync_to_async
from django.db.models import Q

# Create your tests here.
class ImsTests(TestCase):
    # Initializer
    def setUp(self):
        self.holder = User.objects.create(email="tujz23@mails.tsinghua.edu.cn", name="tujz", password=encrypt_text("123456"), user_info="tujz's account")
        self.holder_id = User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").first().id
        User.objects.create(email="delete@mails.com", name="delete", password=encrypt_text("123456"), deleted=True)
        self.delete_id = User.objects.filter(email='delete@mails.com').first().id
        self.holder_login = {"email": "tujz23@mails.tsinghua.edu.cn", "password": encrypt_text("123456")}


    # def test_a(self):
    #     res = self.client.post('/verify', data={"email": "tujz23@mails.tsinghua.edu.cn"}, content_type='application/json')
    #     self.assertEqual(res.status_code, 200)
    #     self.assertEqual(res.json()['code'], 0)

    # ! Utility functions
    def generate_jwt_token(self, id: int, payload: dict, salt: str):
        # * header
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        # dump to str. remove `\n` and space after `:`
        header_str = json.dumps(header, separators=(",", ":"))
        # use base64url to encode, instead of base64
        header_b64 = b64url_encode(header_str)
        
        # * payload
        payload_str = json.dumps(payload, separators=(",", ":"))
        payload_b64 = b64url_encode(payload_str)
        
        # * signature
        signature_str = header_b64 + "." + payload_b64
        signature = hmac.new(salt, signature_str.encode("utf-8"), digestmod=hashlib.sha256).digest()
        signature_b64 = b64url_encode(signature)
        
        return header_b64 + "." + payload_b64 + "." + signature_b64

    
    def generate_header(self, id: int, payload: dict = {}, salt: str = SALT):
        if len(payload) == 0:
            payload = {
                "iat": int(time.time()),
                "exp": int(time.time()) + EXPIRE_IN_SECONDS,
                "data": {
                    "id": id
                }
            }
        return {
            "HTTP_AUTHORIZATION": self.generate_jwt_token(id, payload, salt)
        }

    # ! Test section
    # * Tests for login view
    def test_login_invalid_email(self):
        data = {"email": "invalidemail@com", "password": encrypt_text("123456")}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "Invalid email")

    def test_login_no_existing_user(self):
        data = {"email": "Email1@email.com", "password": encrypt_text("123456")}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        self.assertEqual(res.json()['info'], "User not found")
    
    def test_login_existing_user_wrong_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": encrypt_text("wrongpassword")}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -3)
        self.assertEqual(res.json()['info'], "Wrong password")
    
    def test_login_deleted_user(self):
        data = {"email": "delete@mails.com", "password": encrypt_text("wrongpassword")}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "User deleted or not activated")

    def test_login_existing_user_correct_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": encrypt_text("123456")}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists())

    # * Tests for register view
    def test_reg_name_too_long(self):
        data = {"email": "test@test.com", "password": encrypt_text("123456"), "name": "thisisatoolongusername**************"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        self.assertTrue(User.objects.filter(email="test@test.com").exists() == False)
    
    def test_reg_password_illegal(self):
        data = {"email": "test@test.com", "password": encrypt_text("oops!/wrong"), "name": "testname"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -4)
        self.assertTrue(User.objects.filter(email="test@test.com").exists() == False)
    
    def test_reg_already_exist_user(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": encrypt_text("password"), "name": "tujz2"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -1)
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists())
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").first().name == "tujz")
    
    def test_reg_success_register(self):
        data = {"email": "register@reg.com", "password": encrypt_text("123456"), "name": "register"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)
        self.assertTrue(User.objects.filter(email="register@reg.com").exists())
        self.assertEqual(User.objects.filter(email="register@reg.com").first().deleted, False)

    def test_reg_user_recovery(self):
        data = {"email": "delete@mails.com", "password": encrypt_text("123456"), "name": "delete"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(User.objects.filter(email='delete@mails.com').exists())
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").first().deleted == False)

    # * Tests for delete 
    def test_delete_invalid_jwt(self):
        headers = {"Authorization": "Invalid JWT"}
        res = self.client.delete('/account/delete', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -2)

    def test_delete_missing_jwt(self):
        headers = {}
        res = self.client.delete('/account/delete', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -2)

    def test_delete_expired_jwt(self):
        # email = "tujz23@mails.tsinghua.edu.cn"
        payload = {
            "iat": int(time.time()) - EXPIRE_IN_SECONDS * 2,
            "exp": int(time.time()) - EXPIRE_IN_SECONDS,
            "data": {
                "id": self.holder_id
            }
        }
        headers = self.generate_header(self.holder_id, payload)
        res = self.client.delete('/account/delete', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -2)

    def test_delete_invalid_salt(self):
        headers = self.generate_header(self.holder_id, {}, "AnotherSalt".encode('utf-8'))
        res = self.client.delete('/account/delete', **headers)
        
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -2)

    def test_delete_success(self):
        User.objects.filter(id=self.delete_id).first().deleted = False
        headers = self.generate_header(self.delete_id)
        res = self.client.delete('/account/delete', **headers)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(User.objects.filter(email="delete@mails.com").first().deleted)

    # * Tests for account information 
    def test_info_invalid_jwt(self):
        headers = {"Authorization": "Invalid JWT"}
        res = self.client.delete('/account/delete', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -2)

    def test_info_get_success(self):
        headers = self.generate_header(self.holder_id)
        res = self.client.get('/account/info', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['email'], "tujz23@mails.tsinghua.edu.cn")
        self.assertEqual(res.json()['name'], "tujz")
        self.assertEqual(res.json()['user_info'], "tujz's account")
        self.assertEqual(res.json()['deleted'], False)

    def test_info_get_success2(self):
        headers = self.generate_header(self.delete_id)
        res = self.client.get('/account/info', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['deleted'], True)

    def test_info_wrong_password(self):
        headers = self.generate_header(self.holder_id)
        data = {"origin_password": encrypt_text("123"), "name": "newTujz", "email": "tujz24@mails.tsinghua.edu.cn", "user_info": "new user info"}
        res = self.client.put('/account/info', data=data, content_type='application/json', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -3)
        self.assertEqual(User.objects.filter(id=self.holder_id).first().email, "tujz23@mails.tsinghua.edu.cn")

    def test_info_modify_info(self):
        headers = self.generate_header(self.holder_id)
        data = {"origin_password": encrypt_text("123456"), "name": "newTujz", "password": encrypt_text("654321"), "email": "tujz24@mails.tsinghua.edu.cn", "user_info": "new user info"}
        res = self.client.put('/account/info', data=data, content_type="application/json", **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # 验证成功修改
        modify_info = User.objects.filter(email="tujz24@mails.tsinghua.edu.cn").first()
        self.assertEqual(modify_info.email, "tujz24@mails.tsinghua.edu.cn")
        self.assertEqual(modify_info.name, "newTujz")
        self.assertEqual(modify_info.user_info, "new user info")
        self.assertEqual(modify_info.password, encrypt_text("654321"))
        self.assertEqual(modify_info.deleted, False)
        # 验证tujz23@mails.tsinghua.edu.cn没了
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists() == False)
        # 改回来
        data = {"origin_password": encrypt_text("654321"), "password": encrypt_text("123456"), "name": "tujz", "email": "tujz23@mails.tsinghua.edu.cn", "user_info": "tujz's account"}
        headers = self.generate_header(self.holder_id)
        res = self.client.put('/account/info', data=data, content_type="application/json", **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
    
    # * Tests for search users
    def test_search_users_missing_query1(self):
        headers = self.generate_header(self.holder_id)
        res = self.client.get('/search_user', {'query_name': ''}, **headers)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -7)
    
    def test_search_users_missing_query2(self):
        headers = self.generate_header(self.holder_id)
        res = self.client.get('/search_user', **headers)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -7)
    
    def test_search_users_user_not_found(self):
        headers = self.generate_header(self.holder_id)
        res = self.client.get('/search_user', {'query_name': 'wrong user name'}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['results'], [])
    
    def test_search_users_success(self):
        user1 = User.objects.create(email="email1@email.com", name='user', password=encrypt_text('123456'))
        user2 = User.objects.create(email="email2@email.com", name='user', password=encrypt_text('123456'))
        user3 = User.objects.create(email="email3@email.com", name='user', password=encrypt_text('123456'))
        user4 = User.objects.create(email="email4@email.com", name='user', password=encrypt_text('123456'), deleted=True)
        headers = self.generate_header(self.holder_id)
        res = self.client.get('/search_user', {'query_name': 'user'}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        results = res.json()['results']
        results.sort(key=lambda x:x['user_id'])
        users = [user1, user2, user3]
        self.assertEqual(len(results), len(users))
        for i in range(len(results)):
            self.assertEqual(users[i].email, results[i]['email'])
            self.assertEqual(users[i].name, results[i]['name'])
            self.assertEqual(users[i].deleted, results[i]['deleted'])
            self.assertEqual(results[i]['is_friend'], False)

    # * Utility functions
    def login_for_test(self, data):
        return self.client.post('/account/login', data=data, content_type='application/json').json()['token']

    def add_friend_for_test(self, token, data):
        headers = {"HTTP_AUTHORIZATION": token}
        return self.client.post('/add_friend', data=data, **headers, content_type='application/json')

    def test_search_users_friend(self):
        token = self.login_for_test(self.holder_login)
        user1 = User.objects.create(email="email1@email.com", name='user', password=encrypt_text('123456'))
        user2 = User.objects.create(email="email2@email.com", name='user', password=encrypt_text('123456'))
        user3 = User.objects.create(email="email3@email.com", name='user', password=encrypt_text('123456'))
        user4 = User.objects.create(email="email4@email.com", name='user', password=encrypt_text('123456'), deleted=True)
        data = {"target_id": user1.id, "message": "Hello there!"}
        self.add_friend_for_test(token, data)
        data = {"target_id": user2.id, "message": "Hello there!"}
        self.add_friend_for_test(token, data)
        data = {"target_id": user4.id, "message": "Hello there!"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        self.assertEqual(Request.objects.filter(sender=self.holder, receiver=user4).exists(), False)
        data = {"target_id": self.holder_id, "message": "Hello there!"}
        user3_login = {"email": user3.email, "password": user3.password}
        token3 = self.login_for_test(user3_login)
        self.add_friend_for_test(token3, data)
        headers = self.generate_header(user1.id)
        data = {"sender_user_id": self.holder_id, "receiver_user_id": user1.id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        headers = self.generate_header(user2.id)
        data = {"sender_user_id": self.holder_id, "receiver_user_id": user2.id}
        self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        headers = self.generate_header(self.holder_id)
        data = {"sender_user_id": user3.id, "receiver_user_id": self.holder_id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.client.get('/search_user', {'query_name': 'user'}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        results = res.json()['results']
        results.sort(key=lambda x:x['user_id'])
        users = [user1, user2, user3]
        self.assertEqual(len(results), len(users))
        for i in range(len(results)):
            self.assertEqual(users[i].email, results[i]['email'])
            self.assertEqual(users[i].name, results[i]['name'])
            self.assertEqual(users[i].deleted, results[i]['deleted'])
            if i == 0 or i == 2:
                self.assertEqual(results[i]['is_friend'], True)
            else:
                self.assertEqual(results[i]['is_friend'], False)

    # * Tests for friends portion
    def test_add_friend_user_not_found1(self):
        token = self.login_for_test(self.holder_login)
        data = {"target_id": 3, "message": "Hello"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

    def test_add_friend_user_not_found2(self):
        token = self.login_for_test(self.holder_login)
        temp_user = User.objects.create(email="temp_email@email.com", name='temp_user', password=encrypt_text('123456'), deleted=True)
        data = {"target_id": temp_user.id, "message": "Hello"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

    def test_add_friend_youself(self):
        token = self.login_for_test(self.holder_login)
        data = {"target_id": self.holder_id, "message": "Hello"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -6)
    
    def test_add_friend_success_and_already_send(self):
        token = self.login_for_test(self.holder_login)
        temp_user = User.objects.create(email="temp_email@email.com", name='temp_user', password=encrypt_text('123456'))
        data = {"target_id": temp_user.id, "message": "Hello there!"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"target_id": temp_user.id, "message": "Hello there too!"}
        res = self.add_friend_for_test(token, data)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -5)
        this_request = Request.objects.filter(sender=self.holder, receiver=temp_user, status=0).first()
        # time = this_request.time
        # dt_object = datetime.datetime.fromtimestamp(time)
        # readable_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
        # print(f'\n{readable_time}\n')
        self.assertEqual(this_request.message, "Hello there!")

    def test_add_friend_already_friend(self):
        token = self.login_for_test(self.holder_login)
        temp_user = User.objects.create(email="temp_email@email.com", name='temp_user', password=encrypt_text('123456'))
        temp_token = self.login_for_test({"email": temp_user.email, "password": temp_user.password})
        self.add_friend_for_test(temp_token, {"target_id": self.holder_id, "message": "Hello!"})
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"sender_user_id": temp_user.id, "receiver_user_id": self.holder_id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.add_friend_for_test(token, {"target_id": temp_user.id, "message": "Hello"})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -4)
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user', password=encrypt_text('123456'))
        temp_token = self.login_for_test({"email": temp_user.email, "password": temp_user2.password})
        self.add_friend_for_test(temp_token, {"target_id": self.holder_id, "message": "Hello!"})
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"sender_user_id": temp_user2.id, "receiver_user_id": self.holder_id}
        self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.add_friend_for_test(token, {"target_id": temp_user2.id, "message": "Hello"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
    
    def test_get_friend_requests_success1(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        tokens = []
        for user in temp_users:
            data = {"email": user.email, "password": user.password}
            tokens.append(self.login_for_test(data)) 
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        data2 = {"target_id": self.holder.id, "message": "Hello from temp_user3!"}
        data3 = {"target_id": self.holder.id, "message": "Hello from temp_user4!"}
        data4 = {"target_id": self.holder.id, "message": "Hello from temp_user5!"}
        data5 = {"target_id": temp_user2.id, "message": "Hello from tujz!"}
        data6 = {"target_id": temp_user2.id, "message": "Hello from temp_user4!"}
        datas = [[tokens[0], data1], [tokens[2], data2], [tokens[3], data3], [tokens[4], data4], [token, data5], [tokens[3], data6]]
        for data in datas:
            self.add_friend_for_test(data[0], data[1])
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print('begin res\n', res.json()['requests'], 'end res\n')
        headers = {"HTTP_AUTHORIZATION": tokens[1]}
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print('begin res\n', res.json()['requests'], 'end res\n')
        headers = {"HTTP_AUTHORIZATION": tokens[2]}
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['requests'], [])

    def test_get_friend_requests_success2(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        tokens = []
        for user in temp_users:
            data = {"email": user.email, "password": user.password}
            tokens.append(self.login_for_test(data)) 
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        data2 = {"target_id": self.holder.id, "message": "Hello from temp_user3!"}
        data3 = {"target_id": self.holder.id, "message": "Hello from temp_user4!"}
        data4 = {"target_id": self.holder.id, "message": "Hello from temp_user5!"}
        data5 = {"target_id": temp_user3.id, "message": "Hello from tujz!"}
        datas = [[tokens[0], data1], [tokens[2], data2], [tokens[3], data3], [tokens[4], data4], [token, data5]]
        for data in datas:
            self.add_friend_for_test(data[0], data[1])
        headers = {"HTTP_AUTHORIZATION": tokens[2]}
        data = {"sender_user_id": self.holder_id, "receiver_user_id": temp_user3.id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        data = {"sender_user_id": temp_user4.id, "receiver_user_id": self.holder_id}
        self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print('begin res\n', res.json()['requests'], 'end res\n')
    
    def test_friend_request_handle_deleted(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        data = {"email": temp_user1.email, "password": temp_user1.password}
        token1 = self.login_for_test(data)
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        data = {"email": temp_user2.email, "password": temp_user2.password}
        token2 = self.login_for_test(data)
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        data2 = {"target_id": self.holder.id, "message": "Hello from temp_user2!"}
        self.add_friend_for_test(token1, data1)
        self.add_friend_for_test(token2, data2)
        temp_user1.deleted = True
        temp_user2.deleted = True
        temp_user1.save()
        temp_user2.save()
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"sender_user_id": temp_user2.id, "receiver_user_id": self.holder_id}
        res = self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
    
    def test_friend_request_handle_not_found(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -5)
        res = self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -5)

    def test_friend_request_handle_already_friends(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        data = {"email": temp_user1.email, "password": temp_user1.password}
        token1 = self.login_for_test(data)
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        res = self.add_friend_for_test(token1, data1)
        self.assertEqual(res.status_code, 200)
        data2 = {"target_id": temp_user1.id, "message": "Hello from tujz"}
        res = self.add_friend_for_test(token, data2)
        self.assertEqual(res.status_code, 200)
        data = {"sender_user_id": self.holder_id, "receiver_user_id": temp_user1.id}
        headers1 = {"HTTP_AUTHORIZATION": token1}
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.post('/friend_request_handle', data=data, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), True)
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -4)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), True)
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -4)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), True)

    def test_friend_request_handle_success(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        data = {"email": temp_user1.email, "password": temp_user1.password}
        token1 = self.login_for_test(data)
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        data = {"email": temp_user2.email, "password": temp_user2.password}
        token2 = self.login_for_test(data)
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        data2 = {"target_id": self.holder.id, "message": "Hello from temp_user2!"}
        self.add_friend_for_test(token1, data1)
        self.add_friend_for_test(token2, data2)
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=temp_user1).filter(members=self.holder).exists(), True)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), True)
        self.assertEqual(Request.objects.filter(sender=temp_user1, receiver=self.holder).first().status, 1)
        data = {"sender_user_id": temp_user2.id, "receiver_user_id": self.holder_id}
        res = self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=temp_user2).filter(members=self.holder).exists(), False)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user2).exists(), False)
        self.assertEqual(Request.objects.filter(sender=temp_user2, receiver=self.holder).first().status, 2)
        
    def test_friend_request_handle_send_again_sucdess(self):
        token = self.login_for_test(self.holder_login)
        # A给B发请求，B拒绝，验证conv和req，A给B再发请求，验证conv和req，B同意，验证conv和req
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        data = {"email": temp_user1.email, "password": temp_user1.password}
        token1 = self.login_for_test(data)
        headers = {"HTTP_AUTHORIZATION": token}
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        res = self.add_friend_for_test(token1, data1)
        self.assertEqual(res.status_code, 200)
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        # print("B 拒绝：")
        res = self.client.delete('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), False)
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        # print('begin res\n', res.json()['requests'], 'end res\n')
        # A再给B发请求
        # print("A 再给 B 发请求：")
        data1 = {"target_id": self.holder.id, "message": "Hello from temp_user1!"}
        res = self.add_friend_for_test(token1, data1)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), False)
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        # print('begin res\n', res.json()['requests'], 'end res\n')
        
        # B同意
        # print("B 同意：")
        data = {"sender_user_id": temp_user1.id, "receiver_user_id": self.holder_id}
        res = self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), True)
        res = self.client.get('/friend_requests', **headers)
        self.assertEqual(res.status_code, 200)
        # print('begin res\n', res.json()['requests'], 'end res\n')

    def test_get_friends_list_no_friend(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.get('/friends', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['friends'], [])
    
    def test_get_friends_list_success1(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user3, temp_user4]
        for user in temp_users:
            new_conv = Conversation(type=0)
            new_conv.save()
            new_conv.members.add(self.holder, user)
        res = self.client.get('/friends', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print(res.json()['friends'])
        token1 = self.login_for_test({"email": temp_user1.email, "password": temp_user1.password})
        headers1 = {"HTTP_AUTHORIZATION": token1}
        res = self.client.get('/friends', **headers1)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print(res.json()['friends'])
    
    def test_get_friends_list_success2(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        for user in temp_users:
            new_conv = Conversation(type=0)
            new_conv.save()
            new_conv.members.add(self.holder, user)
        res = self.client.get('/friends', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print(res.json()['friends'])
        # 删掉几个朋友之后再看看：tujz删掉2，5删掉tujz，查看tujz、3、5
        token5 = self.login_for_test({"email": temp_user5.email, "password": temp_user5.password})
        headers5 = {"HTTP_AUTHORIZATION": token5}
        self.client.delete('/manage_friends', data={"friend_id": temp_user2.id}, **headers, content_type='application/json')
        self.client.delete('/manage_friends', data={"friend_id": self.holder_id}, **headers5, content_type='application/json')
        headers3 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user3.email, "password": temp_user3.password})}
        res = self.client.get('/friends', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print("\nTujz: ", res.json()['friends'], '\n')
        res = self.client.get('/friends', **headers3)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # print("\ntemp_user3: ", res.json()['friends'], '\n')
        res = self.client.get('/friends', **headers5)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['friends'], [])

    def test_manage_friends_delete_friend_not_found(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.delete('/manage_friends', data={"friend_id": 3}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
    
    def test_manage_friends_delete_friend_already_not_friend(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        res = self.client.delete('/manage_friends', data={"friend_id": temp_user1.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -3)
        new_conv = Conversation(type=0)
        new_conv.save()
        new_conv.members.add(self.holder, temp_user1)
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user1.email, "password": temp_user1.password})}
        res = self.client.delete('/manage_friends', data = {"friend_id": self.holder_id}, **headers1, content_type = 'application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), False)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=temp_user1).filter(members=self.holder).exists(), False)
        res = self.client.delete('/manage_friends', data = {"friend_id": temp_user1.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -3)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=temp_user1).exists(), False)
        self.assertEqual(Conversation.objects.filter(type=0).filter(members=temp_user1).filter(members=self.holder).exists(), False)
    
    def test_manage_friends_test(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        user = User.objects.create(email="user@email.com", name='user', password=encrypt_text('123456'))
        token1 = self.login_for_test({"email": user.email, "password": user.password})
        headers1 = {"HTTP_AUTHORIZATION": token1}
        # A添加B，B同意，查看Afriendlist，B删掉，查看Bfriendlist，A添加B，B同意，查看A、Bfriendlist
        data = {"target_id": user.id, "message": "Hello!"}
        self.add_friend_for_test(token, data)
        data = {"sender_user_id": self.holder_id, "receiver_user_id": user.id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.client.get('/friends', **headers)
        # print('\nFirst step: ', res.json()['friends'], '\n')
        # print('\nRequest list: ', Request.objects.all(), '\n')

        res = self.client.delete('/manage_friends', data={"friend_id": self.holder_id}, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.get('/friends', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['friends'], [])
        res = self.client.get('/friends', **headers1)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['friends'], [])
        # print('\nRequest list: ', Request.objects.all(), '\n')

        data = {"target_id": user.id, "message": "Hello!"}
        self.add_friend_for_test(token, data)
        data = {"sender_user_id": self.holder_id, "receiver_user_id": user.id}
        self.client.post('/friend_request_handle', data=data, **headers, content_type='application/json')
        res = self.client.get('/friends', **headers)
        # print('\nSecond step: ', res.json()['friends'], '\n')
        res = self.client.get('/friends', **headers1)
        # print('\n  ', res.json()['friends'], '\n')
        # print('\nRequest list: ', Request.objects.all(), '\n')

    # * Tests for groups portion
    def add_five_friends_for_test(self, headers):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        for temp_user in temp_users:
            data = {"target_id": temp_user.id, "message": "Hello"}
            res = self.client.post('/add_friend', data=data, **headers, content_type='application/json')
            self.assertEqual(res.status_code, 200)
            login = {"email": temp_user.email, "password": temp_user.password}
            token = self.login_for_test(login)
            headers1 = {"HTTP_AUTHORIZATION": token}
            data = {"sender_user_id": self.holder_id, "receiver_user_id": temp_user.id}
            res = self.client.post('/friend_request_handle', data=data, **headers1, content_type='application/json')
            self.assertEqual(res.status_code, 200)
        # for conversation in Conversation.objects.all():
        #     print("type: ", conversation.type, " id: ", conversation.id, "\nmembers: ")
        #     for member in conversation.members.all():
        #         print(member, end=' ')
        #     print(end='\n')
        return [temp_user1.id, temp_user2.id, temp_user3.id, temp_user4.id, temp_user5.id]
    
    def test_groups_no_groups(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.get('/groups', **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['groups'], [])
        self.add_five_friends_for_test(headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['groups'], [])
        
    def test_groups_create_groups(self):
        token = self.login_for_test(self.holder_login)
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"name": "groupname"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        res = self.client.get('/groups', **headers)
        self.assertEqual(res.status_code, 200)
        # for group_temp in res.json()['groups']:
        #     group = Group.objects.filter(id=group_temp['id'], name=group_temp['name']).first()
        #     print("id: ", group.id, " name: ", group.name, " owner: ", group.owner, " members: ", group.members.all())
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], -1)
        login = {"email": temp_user1.email, "password": temp_user1.password}
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test(login)}
        res = self.client.post('/groups', data=data, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"name": "groupname1"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"name": ""}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -2)
    
    def test_manage_groups_get(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.get('/groups/manage_groups', {"group_id": "1"}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"name": "groupname"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        res = self.client.get('/groups/manage_groups', {"group_id": f"{Group.objects.filter(name='groupname').first().id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)

    def test_manage_groups_put(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"name": "groupname1"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"name": "groupname2"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        id2 = Group.objects.filter(name='groupname2').first().id
        data = {"group_id": f"{id2 + 1}", "new_name": "groupname3"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{id2}", "new_name": "groupname1"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{id2}", "new_name": "groupname3"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        id1 = Group.objects.filter(name='groupname1').first().id
        data = {"group_id": f"{id1}", "new_name": "groupname2"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"group_id": f"{id1}", "new_name": "groupname2"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)

    def test_manage_groups_delete(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"name": "groupname1"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"name": "groupname2"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        id2 = Group.objects.filter(name='groupname2').first().id
        data = {"group_id": f"{id2 + 1}"}
        res = self.client.delete('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{id2}"}
        res = self.client.delete('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"group_id": f"{id2}"}
        res = self.client.delete('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{id2}", "new_name": "groupname3"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{Group.objects.filter(name='groupname1').first().id}", "new_name": "groupname2"}
        res = self.client.put('/groups/manage_groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
    
    def test_manage_groups_members_get(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"name": "groupname1"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"name": "groupname2"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.get('/groups/members', {"group_id": f"{Group.objects.filter(name='groupname2').first().id + 1}"}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        res = self.client.get('/groups/members', {"group_id": f"{Group.objects.filter(name='groupname2').first().id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertEqual(res.json()['members'], [])
    
    def add_five_friends_to_groups_for_test(self, headers):
        ids = self.add_five_friends_for_test(headers)
        data = {"name": "groupname1"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        data = {"name": "groupname2"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        data = {"name": "groupname3"}
        res = self.client.post('/groups', data=data, **headers, content_type='application/json')
        groupids = [Group.objects.filter(name='groupname1').first().id, Group.objects.filter(name='groupname2').first().id, Group.objects.filter(name='groupname3').first().id]
        data = {"group_id": f"{groupids[0]}", "member_id": f"{ids[0]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"group_id": f"{groupids[0]}", "member_id": f"{ids[2]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"group_id": f"{groupids[0]}", "member_id": f"{ids[3]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"group_id": f"{groupids[1]}", "member_id": f"{ids[4]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {"group_id": f"{groupids[1]}", "member_id": f"{ids[3]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/members', {"group_id": f"{group.id}"}, **headers)
        #     print(res.json()['members'], end='\n\n')
        return [ids, groupids]

    def test_manage_groups_members_post(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        ids = self.add_five_friends_to_groups_for_test(headers)
        temp_user6 = User.objects.create(email="temp_email6@email.com", name='temp_user6', password=encrypt_text('123456'))
        data = {"group_id": f"{ids[1][2] + 1}", "member_id": f"{ids[0][1]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4] + 1}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4]}"}
        res = self.client.post('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
    
    def test_manage_groups_members_delete(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        ids = self.add_five_friends_to_groups_for_test(headers)
        temp_user6 = User.objects.create(email="temp_email6@email.com", name='temp_user6', password=encrypt_text('123456'))
        data = {"group_id": f"{ids[1][2] + 1}", "member_id": f"{ids[0][0]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4] + 1}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][0]}", "member_id": f"{ids[0][4]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][2] + 1}", "member_id": f"{ids[0][1]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4] + 1}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        data = {"group_id": f"{ids[1][1]}", "member_id": f"{ids[0][4]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        data = {"group_id": f"{ids[1][0]}", "member_id": f"{ids[0][3]}"}
        res = self.client.delete('/groups/members', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/members', {"group_id": f"{group.id}"}, **headers)
        #     print(res.json()['members'], end='\n\n')

    # 1: 3, 5, 6  2: 6, 7
    def test_manage_friends_get(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        ids = self.add_five_friends_to_groups_for_test(headers)
        temp_user6 = User.objects.create(email="temp_email6@email.com", name='temp_user6', password=encrypt_text('123456'))
        res = self.client.get('/manage_friends', {"friend_id": f"{temp_user6.id}"}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        for i in range(5):
            res = self.client.get('/manage_friends', {"friend_id": f"{ids[0][i]}"}, **headers)
            self.assertEqual(res.status_code, 200)
            # print('\n', res.json(), '\n')
            # input()

    def test_manage_friends_delete(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        ids = self.add_five_friends_to_groups_for_test(headers)
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/manage_groups', {"group_id": f"{group.id}"}, **headers)
        #     print('\n', res.json(), '\n')
        res = self.client.delete('/manage_friends', data={"friend_id": f"{ids[0][3]}"}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # input()
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/manage_groups', {"group_id": f"{group.id}"}, **headers)
        #     print('\n', res.json(), '\n')

    def test_manage_friends_delete2(self):
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        ids = self.add_five_friends_to_groups_for_test(headers)
        login1 = {"email": "temp_email4@email.com", "password": encrypt_text("123456")}
        token1 = self.login_for_test(login1)
        headers1 = {"HTTP_AUTHORIZATION": token1}
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/manage_groups', {"group_id": f"{group.id}"}, **headers)
        #     print('\n', res.json(), '\n')
        res = self.client.delete('/manage_friends', data={"friend_id": f"{self.holder_id}"}, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # input()
        # for group in Group.objects.all():
        #     res = self.client.get('/groups/manage_groups', {"group_id": f"{group.id}"}, **headers)
        #     print('\n', res.json(), '\n')

    async def test_add_delete_friend_websocket(self):
        async_post = sync_to_async(self.client.post, thread_sensitive=True)
        password = await sync_to_async(encrypt_text)('123456')
        user = await sync_to_async(User.objects.create)(email="user@email.com", name='user', password=password)

        token1 = await sync_to_async(self.login_for_test)({"email": user.email, "password": user.password})
        # communicator = WebsocketCommunicator(application, f"/ws/?token={token1}")
        # connected, _ = await communicator.connect()
        # self.assertTrue(connected)

        token = await sync_to_async(self.login_for_test)(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        data = {"target_id": user.id, "message": "Hello"}
        res = await async_post('/add_friend', data=data, **headers, content_type='application/json')

        self.assertEqual(res.status_code, 200)
        # response = await communicator.receive_json_from()
        # self.assertEqual(response['type'], 'request_message')

        conv = Conversation(type=0)
        await sync_to_async(conv.save)()
        await sync_to_async(conv.members.add)(self.holder, user)

        async_delete = sync_to_async(self.client.delete, thread_sensitive=True)
        res = await async_delete('/manage_friends', data={"friend_id": f"{user.id}"}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # response = await communicator.receive_json_from()
        # self.assertEqual(response['type'], 'delete_friend')

    def test_search_user_detail(self):
        user = User.objects.create(email="user@email.com", name='user', password=encrypt_text('123456'))
        token = self.login_for_test(self.holder_login)
        headers = {"HTTP_AUTHORIZATION": token}
        res = self.client.get('/search_user_detail', {"userId": f"{user.id + 1}"}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        res = self.client.get('/search_user_detail', {"userId": f"{user.id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['user']['is_friend'], False)

        conv = Conversation(type=0)
        conv.save()
        conv.members.add(self.holder, user)
        res = self.client.get('/search_user_detail', {"userId": f"{user.id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['user']['is_friend'], True)

# ====================================================================================================
    
    # * Tests for messages portion
    def send_messages_for_test(self, headers, convId, content="Hello there!"):
        data = {"conversationId": f"{convId}", "content": content}
        res = self.client.post('/conversations/messages', data=data, **headers, content_type='application/json')
        return res

    def add_friends_convs_for_test(self, headers1, headers2, senderId, targetId):
        res = self.client.post('/add_friend', data={"target_id": targetId, "message": "Hello"}, **headers1, content_type='application/json')
        res = self.client.post('/friend_request_handle', data={"sender_user_id": senderId, "receiver_user_id": targetId}, **headers2, content_type='application/json')

    async def test_messages_post_success(self):
        async_post = sync_to_async(self.client.post, thread_sensitive=True)
        password = await sync_to_async(encrypt_text)('123456')
        user = await sync_to_async(User.objects.create)(email="user@email.com", name='user', password=password)

        token = await sync_to_async(self.login_for_test)(self.holder_login)
        token1 = await sync_to_async(self.login_for_test)({"email": user.email, "password": user.password})
        headers = {"HTTP_AUTHORIZATION": token}
        headers1 = {"HTTP_AUTHORIZATION": token1}
        await sync_to_async(self.add_friends_convs_for_test)(headers, headers1, self.holder_id, user.id)
        # communicator = WebsocketCommunicator(application, f"/ws/?token={token1}")
        # connected, _ = await communicator.connect()
        # self.assertTrue(connected)

        conv_query = await sync_to_async(Conversation.objects.filter)(type=0)
        conv_query = await sync_to_async(conv_query.filter)(members=self.holder)
        conv_query = await sync_to_async(conv_query.filter)(members=user)
        conv = await sync_to_async(conv_query.first)()

        res = await sync_to_async(self.send_messages_for_test)(headers, conv.id)
        self.assertEqual(res.status_code, 200)

        # response = await communicator.receive_json_from()
        # self.assertEqual(response['type'], 'notify')

    async def test_messages_post_failed(self):
        async_post = sync_to_async(self.client.post, thread_sensitive=True)
        password = await sync_to_async(encrypt_text)('123456')
        user = await sync_to_async(User.objects.create)(email="user@email.com", name='user', password=password)

        token = await sync_to_async(self.login_for_test)(self.holder_login)
        token1 = await sync_to_async(self.login_for_test)({"email": user.email, "password": user.password})
        headers = {"HTTP_AUTHORIZATION": token}
        headers1 = {"HTTP_AUTHORIZATION": token1}
        await sync_to_async(self.add_friends_convs_for_test)(headers, headers1, self.holder_id, user.id)
        conv_query = await sync_to_async(Conversation.objects.filter)(type=0)
        conv_query = await sync_to_async(conv_query.filter)(members=self.holder)
        conv_query = await sync_to_async(conv_query.filter)(members=user)
        conv = await sync_to_async(conv_query.first)()

        res = await sync_to_async(self.send_messages_for_test)(headers, conv.id + 1)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        await sync_to_async(conv.members.add)(self.holder)
        res = await sync_to_async(self.send_messages_for_test)(headers, conv.id, "")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)

        res = await sync_to_async(self.send_messages_for_test)(headers, conv.id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)

    def test_messages_get(self):
        user = User.objects.create(email="user@email.com", name='user', password=encrypt_text('123456'))

        token = self.login_for_test(self.holder_login)
        token1 = self.login_for_test({"email": user.email, "password": user.password})
        headers = {"HTTP_AUTHORIZATION": token}
        headers1 = {"HTTP_AUTHORIZATION": token1}
        self.add_friends_convs_for_test(headers, headers1, self.holder_id, user.id)
        conv = Conversation.objects.filter(type=0).filter(members=self.holder).filter(members=user).first()

        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})}
        res = self.client.get('/conversations/messages', {"conversationId": conv.id + 1}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        res = self.send_messages_for_test(headers, conv.id)
        self.assertEqual(res.status_code, 200)
        res = self.send_messages_for_test(headers, conv.id)
        self.assertEqual(res.status_code, 200)
        res = self.send_messages_for_test(headers1, conv.id)
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/messages', {"conversationId": conv.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(res.json()['messages'])
        # input()
        res = self.client.get('/conversations/messages', {"conversationId": conv.id}, **headers1)
        self.assertEqual(res.status_code, 200)
        # print(res.json()['messages'])

    # * Tests for conversations portion
    def create_conversations_for_test(self):
        # *1*, 3, 4为一组；2，*3*，5为一组
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        
        headers = []
        for user in temp_users:
            token = self.login_for_test({"email": user.email, "password": user.password})
            headers.append({"HTTP_AUTHORIZATION": token})
        
        for i in range(len(temp_users)):
            for j in range(len(temp_users)):
                user1 = temp_users[i]
                user2 = temp_users[j]
                if user1 != user2:
                    if not (Conversation.objects.filter(type=0).filter(members=user1).filter(members=user2).exists()):
                        self.add_friends_convs_for_test(headers[i], headers[j], user1.id, user2.id)

        data = {
            "members": [temp_user3.id, temp_user4.id, temp_user5.id + 1],
            "name": "conv1"
        }
        res = self.client.post('/conversations', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        data = {
            "members": [temp_user3.id, temp_user4.id],
            "name": "conv1"
        }
        res = self.client.post('/conversations', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        data = {
            "members": [temp_user2.id, temp_user5.id],
            "name": "conv2"
        }
        res = self.client.post('/conversations', data=data, **headers[2], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        return {"temp_users": temp_users, "headers": headers, "convs": [
            Conversation.objects.filter(type=1).filter(ConvName="conv1").first().id,
            Conversation.objects.filter(type=1).filter(ConvName="conv2").first().id
        ]}

    def test_conversations_post(self):
        self.create_conversations_for_test()

    def test_conversations_get(self):
        convs = self.create_conversations_for_test()
        
        res = self.client.get('/conversations', **convs["headers"][0])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # input()

        res = self.client.get('/conversations', **convs["headers"][2])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))

        res = self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][0]}", "content": "from user3"}, **convs["headers"][2], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][0]}", "content": "from user1"}, **convs["headers"][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][1]}", "content": "from user3"}, **convs["headers"][2], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][0]}", "content": "from user3"}, **convs["headers"][2], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][0]}", "content": "from user4"}, **convs["headers"][3], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{convs['convs'][1]}", "content": "from user5"}, **convs["headers"][4], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": Conversation.objects.filter(type=0).filter(members=convs["temp_users"][0]).filter(members=convs["temp_users"][2]).first().id, "content": "private from user1"}, **convs["headers"][0], content_type='application/json')

        res = self.client.get('/conversations', **convs["headers"][2])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # print(res.json()['conversation'][0])
        # input()

        self.client.get('/conversations/messages', {"conversationId": f"{convs['convs'][0]}"}, **convs['headers'][2])
        self.client.get('/conversations/messages', {"conversationId": f"{convs['convs'][1]}"}, **convs['headers'][4])

        res = self.client.get('/conversations', **convs["headers"][2])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))

    def test_interface(self):
        convs = self.create_conversations_for_test()

        self.client.post('/conversations/messages', data={"conversationId": f'{convs["convs"][0]}', "content": "from user3"}, **convs["headers"][2], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f'{convs["convs"][0]}', "content": "from user1"}, **convs["headers"][0], content_type='application/json')

        res = self.client.get('/interface', {"conversationId": f'{convs["convs"][1] + 1}'}, **convs["headers"][3])
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        res = self.client.get('/interface', {"conversationId": f'{convs["convs"][0]}'}, **convs["headers"][3])
        self.assertEqual(res.status_code, 200)
        # print(res.json())
        # input()

        self.client.get('/conversations/messages', {"conversationId": f'{convs["convs"][0]}'}, **convs['headers'][3])
        data = {
            "conversationId": f"{convs['convs'][1] + 1}",
            "ontop": True,
            "unreads": True
        }
        res = self.client.post('/interface', data=data, **convs['headers'][3], content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        data = {
            "conversationId": f"{convs['convs'][0]}",
            "ontop": True,
            "unreads": True
        }
        res = self.client.post('/interface', data=data, **convs['headers'][3], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        
        res = self.client.get('/interface', {"conversationId": f'{convs["convs"][0]}'}, **convs["headers"][3])
        self.assertEqual(res.status_code, 200)
        # print(res.json())

    def test_manage_admin(self):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        data = {
            "members": [temp_user1.id, temp_user2.id, temp_user3.id, temp_user4.id],
            "name": "conv"
        }
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        for user in temp_users:
            self.add_friends_convs_for_test(headers, {"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})}, self.holder_id, user.id)

        res = self.client.post('/conversations', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        conv = Conversation.objects.filter(type=1).filter(ConvName="conv").first()

        # print("creator: ", conv.creator)
        # print("manager: ", conv.managers.all())
        # print("member: ", conv.members.all())
        data = {
            "conversation_id": conv.id,
            "user": temp_user5.id + 1
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        data = {
            "conversation_id": conv.id,
            "user": temp_user5.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 1)

        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        # print("creator: ", conv.creator)
        # print("manager: ", conv.managers.all())
        # print("member: ", conv.members.all())
        
        data = {
            "conversation_id": conv.id,
            "user": temp_user2.id
        }
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user1.email, "password": temp_user1.password})}
        res = self.client.post('/conversations/manage/admin', data=data, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)
        
        data = {
            "conversation_id": conv.id,
            "user": temp_user2.id
        }
        headers3 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user3.email, "password": temp_user3.password})}
        res = self.client.post('/conversations/manage/admin', data=data, **headers3, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], 3)

        data = {
            "conversation_id": conv.id,
            "user": self.holder_id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')

        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], 3)

        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.delete('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        # print("creator: ", conv.creator)
        # print("manager: ", conv.managers.all())
        # print("member: ", conv.members.all())

    def test_reply_messages(self):
        temp_user = User.objects.create(email="temp_email@email.com", name='temp_user', password=encrypt_text('123456'))
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user.email, "password": temp_user.password})}
        self.add_friends_convs_for_test(headers, headers1, self.holder_id, temp_user.id)

        conv = Conversation.objects.filter(type=0).filter(members=temp_user).filter(members=self.holder).first()

        self.client.post('/conversations/messages', data={"conversationId": f"{conv.id}", "content": "tujz: balabala"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv.id}", "content": "user: balabala"}, **headers1, content_type='application/json')

        res = self.client.get('/conversations/messages', {"conversationId": f"{conv.id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()

        msg1 = Message.objects.filter(content="tujz: balabala").first()
        msg2 = Message.objects.filter(content="user: balabala").first()
        res = self.client.post('/conversations/messages', data={"conversationId": f"{conv.id}", "content": "tujz: reply to msg2", "reply_to": msg2.id + 1}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -4)
        res = self.client.post('/conversations/messages', data={"conversationId": f"{conv.id}", "content": "tujz: reply to msg2", "reply_to": msg2.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        msg3 = Message.objects.filter(content="tujz: reply to msg2").first()
        res = self.client.post('/conversations/messages', data={"conversationId": f"{conv.id}", "content": "last", "reply_to": msg3.id}, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/messages', {"conversationId": f"{conv.id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()
        res = self.client.get('/conversations/messages', {"conversationId": f"{conv.id}"}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))

        res = self.client.get('/conversations/get_reply', {"message_id": msg3.id + 2}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        
        res = self.client.get('/conversations/get_reply', {"message_id": msg2.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['replies'], indent=4, ensure_ascii=False))
        # input()

        res = self.client.get('/conversations/get_reply', {"message_id": msg3.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['replies'], indent=4, ensure_ascii=False))

    def test_manage_info(self):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        data = {
            "members": [temp_user1.id, temp_user2.id, temp_user3.id, temp_user4.id, temp_user5.id],
            "name": "conv"
        }
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        for user in temp_users:
            self.add_friends_convs_for_test(headers, {"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})}, self.holder_id, user.id)

        res = self.client.post('/conversations', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        conv = Conversation.objects.filter(type=1).filter(ConvName="conv").first()

        res = self.client.post('/conversations/manage/info', data={"conversation_id": conv.id + 1, "name": "Newname"}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user1.email, "password": temp_user1.password})}
        res = self.client.post('/conversations/manage/info', data={"conversation_id": conv.id, "name": "Newname"}, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.post('/conversations/manage/info', data={"conversation_id": conv.id, "name": "Newname"}, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # for convs in Conversation.objects.all():
        #     print(convs.ConvName)

        res = self.client.post('/conversations/manage/info', data={"conversation_id": conv.id, "name": "Newname2"}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # for convs in Conversation.objects.all():
        #     print(convs.ConvName)
    
    def test_ownership_transfer(self):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        data = {
            "members": [temp_user1.id, temp_user2.id, temp_user3.id, temp_user4.id, temp_user5.id],
            "name": "conv"
        }
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        for user in temp_users:
            self.add_friends_convs_for_test(headers, {"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})}, self.holder_id, user.id)
        
        res = self.client.post('/conversations', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        conv = Conversation.objects.filter(type=1).filter(ConvName="conv").first()

        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": temp_user1.email, "password": temp_user1.password})}
        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.post('/conversations/manage/ownership_transfer', data=data, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(Conversation.objects.filter(type=1).filter(ConvName="conv").first().creator)
        # print(Conversation.objects.filter(type=1).filter(ConvName="conv").first().managers.all())

        res = self.client.post('/conversations/manage/ownership_transfer', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(Conversation.objects.filter(type=1).filter(ConvName="conv").first().creator)
        # print(Conversation.objects.filter(type=1).filter(ConvName="conv").first().managers.all())

        res = self.client.post('/conversations/manage/ownership_transfer', data=data, **headers1, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

    def add_managers_for_test(self):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        data = {
            "members": [temp_user1.id, temp_user2.id, temp_user3.id, temp_user4.id, temp_user5.id],
            "name": "conv"
        }
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        for user in temp_users:
            self.add_friends_convs_for_test(headers, {"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})}, self.holder_id, user.id)

        res = self.client.post('/conversations', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        conv = Conversation.objects.filter(type=1).filter(ConvName="conv").first()
        data = {
            "conversation_id": conv.id,
            "user": temp_user1.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {
            "conversation_id": conv.id,
            "user": temp_user3.id
        }
        res = self.client.post('/conversations/manage/admin', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        header = []
        for user in temp_users:
            header.append({"HTTP_AUTHORIZATION": self.login_for_test({"email": user.email, "password": user.password})})
        return [temp_users, conv, header]
        # 1, 3是管理员, holder是群主

    def test_notification(self):
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}
        res = self.client.get('/conversations/manage/notifications', {"conversation_id": conv[1].id + 1}, **headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        res = self.client.get('/conversations/manage/notifications', {"conversation_id": conv[1].id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(res.json()['notifications'])
        # input()

        data = {
            "conversation_id": conv[1].id,
            "content": "notif from tujz",
        }
        res = self.client.post('/conversations/manage/notifications', data=data, **conv[2][1], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        res = self.client.post('/conversations/manage/notifications', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = {
            "conversation_id": conv[1].id,
            "content": "notif from user1",
        }
        res = self.client.post('/conversations/manage/notifications', data=data, **conv[2][0], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/manage/notifications', {"conversation_id": conv[1].id}, **conv[2][0])
        self.assertEqual(res.status_code, 200)
        # print(res.json()['notifications'])
        # input()

        notif1 = Notification.objects.filter(content="notif from tujz").first()
        notif2 = Notification.objects.filter(content="notif from user1").first()
        data = {
            "notification_id": notif1.id,
        }
        res = self.client.delete('/conversations/manage/notifications', data=data, **conv[2][3], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        res = self.client.delete('/conversations/manage/notifications', data=data, **conv[2][2], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        
        res = self.client.get('/conversations/manage/notifications', {"conversation_id": conv[1].id}, **conv[2][3])
        self.assertEqual(res.status_code, 200)
        # print(res.json()['notifications'])
    
    def test_messages_delete(self):
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}

        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number1 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number2 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number3 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number4 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number5 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number6 from holder"}, **headers, content_type='application/json')
        
        res = self.client.get('/conversations/messages', {"conversationId": f"{conv[1].id}"}, **conv[2][0])

        msg1 = Message.objects.filter(content='number1 from holder').first()
        msg2 = Message.objects.filter(content='number2 from holder').first()
        msg3 = Message.objects.filter(content='number3 from user').first()
        msg4 = Message.objects.filter(content='number4 from holder').first()
        msg5 = Message.objects.filter(content='number5 from user').first()
        msg6 = Message.objects.filter(content='number6 from holder').first()

        res = self.client.delete('/conversations/delete_messages', data={"message_ids": [msg1.id]}, **conv[2][0], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.delete('/conversations/delete_messages', data={"message_ids": [msg6.id + 1]}, **conv[2][0], content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        res = self.client.delete('/conversations/delete_messages', data={"message_ids": [msg2.id, msg4.id]}, **conv[2][0], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/messages', {"conversationId": f'{conv[1].id}'}, **conv[2][0])
        res = self.client.get('/conversations/messages', {"conversationId": f'{conv[1].id}'}, **headers)

        res = self.client.delete('/conversations/delete_messages', data={"message_ids": [msg6.id]}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations', **headers)
        
        res = self.client.delete('/conversations/delete_messages', data={"message_ids": [msg1.id, msg2.id, msg3.id, msg4.id, msg5.id]}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations', **headers)
        res = self.client.get('/conversations', **conv[2][0])

    def test_get_members(self):
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}

        private = Conversation.objects.filter(type=0).filter(members=self.holder).first()
        conver = conv[1]
        res = self.client.get('/conversations/get_members', {"conversation_id": private.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))
        another = private.members.exclude(id=self.holder_id).first()
        # another：temp_user1
        headers1 = {"HTTP_AUTHORIZATION": self.login_for_test({"email": another.email, "password": another.password})}
        res = self.client.get('/conversations/get_members', {"conversation_id": private.id}, **headers1)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))

        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))
        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **conv[2][3])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))

    def test_member_remove(self):
        # 1, 3是管理员, holder是群主
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}

        conver = conv[1]
        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **conv[2][3])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))
        # input()

        res = self.client.post('/conversations/member/remove', data={"conversation_id": conver.id}, **conv[2][3], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **conv[2][3])
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))
        # input()

        res = self.client.post('/conversations/member/remove', data={"conversation_id": conver.id}, **conv[2][3], content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -1)

        res = self.client.delete('/conversations/member/remove', data={"conversation_id": conver.id, "user": conv[0][4].id}, **conv[2][1], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)
        res = self.client.delete('/conversations/member/remove', data={"conversation_id": conver.id, "user": conv[0][0].id}, **conv[2][2], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        res = self.client.delete('/conversations/member/remove', data={"conversation_id": conver.id, "user": conv[0][0].id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.delete('/conversations/member/remove', data={"conversation_id": conver.id, "user": conv[0][4].id}, **conv[2][2], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # 剩余成员：holder，2，3
        
        res = self.client.get('/conversations/get_members', {"conversation_id": conver.id}, **headers)
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json(), indent=4, ensure_ascii=False))
        # input()
        res = self.client.get('/conversations', **conv[2][4])
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # print(conver.id)
        # input()
        
        res = self.client.post('/conversations/member/remove', data={"conversation_id": conver.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        res = self.client.get('/conversations', **headers)
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # input()
        res = self.client.get('/conversations', **conv[2][1])
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # input()

    def test_read_list(self):
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}

        conver = conv[1]
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number1 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number2 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number3 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number4 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number5 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number6 from holder"}, **headers, content_type='application/json')
        
        msg1 = Message.objects.filter(content='number1 from holder').first()
        msg2 = Message.objects.filter(content='number2 from holder').first()
        msg3 = Message.objects.filter(content='number3 from user').first()
        msg4 = Message.objects.filter(content='number4 from holder').first()
        msg5 = Message.objects.filter(content='number5 from user').first()
        msg6 = Message.objects.filter(content='number6 from holder').first()

        res = self.client.post('/conversations/readlist', data={"message_id": msg1.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['read_users'], indent=4, ensure_ascii=False))
        # input()

        self.client.get('/conversations/messages', {"conversationId": conver.id}, **headers)
        res = self.client.post('/conversations/readlist', data={"message_id": msg5.id}, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['read_users'], indent=4, ensure_ascii=False))
        # input()

        conver = Conversation.objects.filter(members=self.holder).filter(members=conv[0][0]).first()
        res = self.client.get('/conversations/messages', {"conversationId": conver.id}, **headers)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()
        res = self.client.get('/conversations/messages', {"conversationId": conver.id}, **conv[2][0])
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
    
    def test_sift(self):
        conv = self.add_managers_for_test()
        headers = {"HTTP_AUTHORIZATION": self.login_for_test(self.holder_login)}

        conver = conv[1]
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number1 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number2 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number3 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number4 from holder"}, **headers, content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number5 from user"}, **conv[2][0], content_type='application/json')
        self.client.post('/conversations/messages', data={"conversationId": f"{conv[1].id}", "content": "number6 from holder"}, **headers, content_type='application/json')

        data = {
            "conversationId": conver.id,
            "sender_id": self.holder_id,
        }
        res = self.client.post('/conversations/sift', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()

        data = {
            "conversationId": conver.id,
            "content": "holder"
        }
        res = self.client.post('/conversations/sift', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()
        
        data = {
            "conversationId": conver.id,
            "start_time": "2023-12-10 10:43:23"
        }
        res = self.client.post('/conversations/sift', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))
        # input()

        data = {
            "conversationId": conver.id,
            "end_time": "2023-12-10 10:43:23"
        }
        res = self.client.post('/conversations/sift', data=data, **headers, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['messages'], indent=4, ensure_ascii=False))

    def test_add_member(self):
        temp_user1 = User.objects.create(email="temp_email1@email.com", name='temp_user1', password=encrypt_text('123456'))
        temp_user2 = User.objects.create(email="temp_email2@email.com", name='temp_user2', password=encrypt_text('123456'))
        temp_user3 = User.objects.create(email="temp_email3@email.com", name='temp_user3', password=encrypt_text('123456'))
        temp_user4 = User.objects.create(email="temp_email4@email.com", name='temp_user4', password=encrypt_text('123456'))
        temp_user5 = User.objects.create(email="temp_email5@email.com", name='temp_user5', password=encrypt_text('123456'))
        temp_users = [temp_user1, temp_user2, temp_user3, temp_user4, temp_user5]
        
        headers = []
        for user in temp_users:
            token = self.login_for_test({"email": user.email, "password": user.password})
            headers.append({"HTTP_AUTHORIZATION": token})
        
        for i in range(len(temp_users)):
            for j in range(len(temp_users)):
                user1 = temp_users[i]
                user2 = temp_users[j]
                if user1 != user2:
                    if not (Conversation.objects.filter(type=0).filter(members=user1).filter(members=user2).exists()):
                        self.add_friends_convs_for_test(headers[i], headers[j], user1.id, user2.id)

        data = {
            "members": [temp_user3.id, temp_user4.id],
            "name": "last_conv"
        }
        res = self.client.post('/conversations', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        # 1，3，4，1为群主
        conv = Conversation.objects.filter(ConvName="last_conv").first()
        data = {
            "conversationId": conv.id,
            "member_id": temp_user3.id,
        }
        res = self.client.post('/conversations/member/add', data=data, **headers[2], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)
        
        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id}, **headers[0])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['invitations'], indent=4, ensure_ascii=False))
        # input() # 空列表

        data = {
            "conversationId": conv.id,
            "member_id": temp_user2.id,
        }
        res = self.client.post('/conversations/member/add', data=data, **headers[2], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        
        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id + 1}, **headers[0])
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)

        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id}, **headers[0])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['invitations'], indent=4, ensure_ascii=False))
        # input() # 一个邀请，status=0

        res = self.client.post('/conversations/member/add', data=data, **headers[2], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -5)

        res = self.client.post('/conversations/member/add', data=data, **headers[3], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id}, **headers[0])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['invitations'], indent=4, ensure_ascii=False))
        # input() # 两个个邀请，status=0

        inv = Invitation.objects.filter(sender=temp_user3, receiver=temp_user2, conversation=conv).first()
        data = {
            "invite_id": inv.id,
        }
        res = self.client.post('/conversations/manage/handle_invitation', data=data, **headers[3], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -3)

        res = self.client.post('/conversations/manage/handle_invitation', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 200)
        
        res = self.client.post('/conversations/manage/handle_invitation', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -4)

        # res = self.client.post('/conversations/manage/handle_invitation', data={"invite_id": 2}, **headers[0], content_type='application/json')
        # self.assertEqual(res.status_code, 403)
        # self.assertEqual(res.json()['code'], -4)

        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id}, **headers[1])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['invitations'], indent=4, ensure_ascii=False))
        # input() # 一个为2一个为3

        data = {
            "conversationId": conv.id,
            "member_id": temp_user5.id,
        }
        res = self.client.post('/conversations/member/add', data=data, **headers[0], content_type='application/json')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/conversations/invitation', {"conversation_id": conv.id}, **headers[1])
        self.assertEqual(res.status_code, 200)
        # print(json.dumps(res.json()['invitations'], indent=4, ensure_ascii=False))
        # input() # 一个为2一个为3一个为2

        res = self.client.get('/conversations', **headers[4])
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # input()

        res = self.client.get('/conversations', **headers[1])
        # print(json.dumps(res.json()['conversation'], indent=4, ensure_ascii=False))
        # input()