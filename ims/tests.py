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
        holder = User.objects.create(email="tujz23@mails.tsinghua.edu.cn", name="tujz", password="123456")

    # ! Utility functions

    # ! Test section
    # * Tests for login view
    def test_login_invalid_email(self):
        data = {"email": "invalidemail.com", "password": "123456"}
        res = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "Invalid email")

    def test_no_existing_user(self):
        data = {"email": "Email1@email.com", "password": "123456"}
        res = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 1)
        self.assertEqual(res.json()['info'], "User not found")
    
    def test_existing_user_wrong_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": "wrongpassword"}
        res = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], 2)
        self.assertEqual(res.json()['info'], "Wrong password")

    def test_existing_user_correct_password(self):
        data = {"email": "tujz23@mails.tsinghua.edu.cn", "password": "123456"}
        res = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)
        self.assertTrue(User.objects.filter(email="tujz23@mails.tsinghua.edu.cn").exists())
