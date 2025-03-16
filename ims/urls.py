from django.urls import path, include
import ims.views as views

urlpatterns = [
    path('login', views.login),
]
