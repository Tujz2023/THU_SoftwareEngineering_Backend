#!/bin/sh

# 运行数据库迁移
python3 manage.py migrate

# 启动 uWSGI
uwsgi --socket mysite.sock \
    --module=mysite.wsgi:application \
    --env DJANGO_SETTINGS_MODULE=baackend.settings \
    --master \
    --processes=5 \
    --harakiri=20 \
    --max-requests=5000 \
    --vacuum \
    --chmod-socket=666
