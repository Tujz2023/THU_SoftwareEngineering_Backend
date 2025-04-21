#!/bin/sh
# service redis-server start

python3 manage.py makemigrations ims
python3 manage.py migrate

daphne -b 0.0.0.0 -p 80 backend.asgi:application 

# # TODO Start: [Student] Run with uWSGI instead
# # python3 manage.py runserver 80
# uwsgi --module=backend.wsgi:application \
#     --env DJANGO_SETTINGS_MODULE=backend.settings \
#     --master \
#     --http=0.0.0.0:80 \
#     --processes=5 \
#     --harakiri=20 \
#     --max-requests=5000 \
#     --vacuum
# # TODO End: [Student] Run with uWSGI instead

# uvicorn backend.asgi:application --host 0.0.0.0 --port 80 --workers 5
