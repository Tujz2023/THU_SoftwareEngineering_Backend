import random
from django.test import TestCase, Client
from ims.models import User
import datetime
import hashlib
import hmac
import time
import json
import base64

from utils.utils_jwt import EXPIRE_IN_SECONDS, SALT, b64url_encode

# Create your tests here.
class ImsTests(TestCase):
    # Initializer
    def setUp(self):
        User.objects.create(email="tujz23@mails.tsinghua.edu.cn", name="tujz", password="123456", user_info="tujz's account")
        self.holder_id = User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").first().id
        User.objects.create(email="delete@mails.com", name="delete", password="123456", deleted=True)
        self.delete_id = User.objects.filter(email='delete@mails.com').first().id

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
        data = {"email": "invalidemail@com", "password": "123456"}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "Invalid email")

    def test_login_no_existing_user(self):
        data = {"email": "Email1@email.com", "password": "123456"}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], -1)
        self.assertEqual(res.json()['info'], "User not found")
    
    def test_login_existing_user_wrong_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": "wrongpassword"}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -3)
        self.assertEqual(res.json()['info'], "Wrong password")
    
    def test_login_deleted_user(self):
        data = {"email": "delete@mails.com", "password": "wrongpassword"}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "User deleted or not activated")

    def test_login_existing_user_correct_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": "123456"}
        res = self.client.post('/account/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists())

    # * Tests for register view
    def test_reg_name_too_long(self):
        data = {"email": "test@test.com", "password": "123456", "name": "thisisatoolongusername**************"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -3)
        self.assertTrue(User.objects.filter(email="test@test.com").exists() == False)
    
    def test_reg_password_illegal(self):
        data = {"email": "test@test.com", "password": "oops!/wrong", "name": "testname"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -4)
        self.assertTrue(User.objects.filter(email="test@test.com").exists() == False)
    
    def test_reg_already_exist_user(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": "password", "name": "tujz2"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], -1)
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists())
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").first().name == "tujz")
    
    def test_reg_success_register(self):
        data = {"email": "register@reg.com", "password": "123456", "name": "register"}
        res = self.client.post('/account/reg', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)
        self.assertTrue(User.objects.filter(email="register@reg.com").exists())
        self.assertEqual(User.objects.filter(email="register@reg.com").first().deleted, False)

    def test_reg_user_recovery(self):
        data = {"email": "delete@mails.com", "password": "123456", "name": "delete"}
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
        data = {"origin_password": "123", "name": "newTujz", "email": "tujz24@mails.tsinghua.edu.cn", "user_info": "new user info"}
        res = self.client.put('/account/info', data=data, content_type='application/json', **headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], -3)
        self.assertEqual(User.objects.filter(id=self.holder_id).first().email, "tujz23@mails.tsinghua.edu.cn")

    def test_info_modify_info(self):
        headers = self.generate_header(self.holder_id)
        data = {"origin_password": "123456", "name": "newTujz", "password": "654321", "email": "tujz24@mails.tsinghua.edu.cn", "user_info": "new user info"}
        res = self.client.put('/account/info', data=data, content_type="application/json", **headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        # 验证成功修改
        modify_info = User.objects.filter(email="tujz24@mails.tsinghua.edu.cn").first()
        self.assertEqual(modify_info.email, "tujz24@mails.tsinghua.edu.cn")
        self.assertEqual(modify_info.name, "newTujz")
        self.assertEqual(modify_info.user_info, "new user info")
        self.assertEqual(modify_info.password, "654321")
        self.assertEqual(modify_info.deleted, False)
        # 验证tujz23@mails.tsinghua.edu.cn没了
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists() == False)
        # 改回来
        data = {"origin_password": "654321", "password": "123456", "name": "tujz", "email": "tujz23@mails.tsinghua.edu.cn", "user_info": "tujz's account"}
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
        user1 = User.objects.create(email="email1@email.com", name='user', password='123456')
        user2 = User.objects.create(email="email2@email.com", name='user', password='123456')
        user3 = User.objects.create(email="email3@email.com", name='user', password='123456')
        user4 = User.objects.create(email="email4@email.com", name='user', password='123456', deleted=True)
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