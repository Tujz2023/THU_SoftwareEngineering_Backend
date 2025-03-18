from django.urls import path, include
import ims.views as views

urlpatterns = [
    path('account/login', views.login),
    path('account/reg', views.register),
    path('account/delete', views.delete),
    path('account/info', views.account_info),
]
