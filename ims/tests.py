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
)
import datetime
import hashlib
import hmac
import time
import json
import base64

from utils.utils_jwt import EXPIRE_IN_SECONDS, SALT, b64url_encode
from utils.utils_crypto import encrypt_text, decrypt_text

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
    #     new_conversation = Conversation(type=0)
    #     new_conversation.members.add(self.holder)
    #     new_conversation.save()
    #     print("ok!")

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
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
    
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

    # * Utility functions
    def login_for_test(self, data):
        return self.client.post('/account/login', data=data, content_type='application/json').json()['token']

    def add_friend_for_test(self, token, data):
        headers = {"HTTP_AUTHORIZATION": token}
        return self.client.post('/add_friend', data=data, **headers, content_type='application/json')

    def test_search_users_friend(self):
        token = self.login_for_test(self.holder_login)

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
        # TODO: 
    
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
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], -7)

    def test_get_friend_requests_success2(self):
        token = self.login_for_test(self.holder_login)
        # TODO: 修改一些状态，让0，1，2，3均存在
    
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
        # TODO: 两个人给对方互相发消息，一个人同意，另一个人也想同意或者删除

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
        