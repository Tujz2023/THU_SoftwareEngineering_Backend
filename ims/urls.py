from django.urls import path, include
import ims.views as views

urlpatterns = [
    path('login', views.login),
    # 登录注册
    # 用户
    path('search_user', views.search_users),
    path('add_friend', views.add_friend),
    path('friend_requests', views.get_friend_requests),
    path('friend_requests/<request_id>', views.friend_request_handle),
    path('groups', views.groups),
    path('groups/<group_id>', views.manage_groups),
    path('groups/<group_id>/members', views.manage_group_members),
    path('friends',views.get_friends_list),
    path('frieds/<friend_id>',views.manage_friends),
]
