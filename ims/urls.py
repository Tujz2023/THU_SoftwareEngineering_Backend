from django.urls import path, include
import ims.views as views

urlpatterns = [
    path('csrf', views.get_csrf_token),
    path('account/login', views.login),
    path('account/reg', views.register),
    path('account/delete', views.delete),
    path('account/info', views.account_info),
    path('search_user', views.search_users),
    path('verify', views.send_verification_email),
    path('add_friend', views.add_friend),
    path('friend_requests', views.get_friend_requests),
    path('friend_request_handle', views.friend_request_handle),
    path('groups', views.groups),
    path('groups/manage_groups', views.manage_groups),
    path('groups/members', views.manage_group_members),
    path('friends',views.get_friends_list),
    path('manage_friends',views.manage_friends),
    path('search_user_detail', views.search_user_detail),
    path('conversations', views.conversation),
    path('conversations/messages', views.message),
    path('conversations/delete_messages', views.delete_messages),
    path('conversations/image', views.image),
    path('conversations/get_reply', views.get_reply),
    path('conversations/get_members', views.get_members),
    path('conversations/manage/admin', views.conv_manage_admin),
    path('conversations/manage/info', views.conv_manage_info),
    path('conversations/manage/ownership_transfer', views.conv_manage_ownership),
    path('conversations/member/remove', views.conv_member_remove),
    path('conversations/member/add', views.conv_member_add),
    path('conversations/invitation', views.conv_invitation),
    path('conversations/manage/handle_invitation', views.conv_handle_invitation),
    path('conversations/manage/notifications', views.conv_manage_notifications),
    path('interface', views.interface),
    path('conversations/readlist', views.read_list),
    path('conversations/sift', views.sift_messages),
    # path('upload', views.upload_image),
]
