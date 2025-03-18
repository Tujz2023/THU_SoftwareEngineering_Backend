# TODO Start: [Student] Complete Dockerfile
FROM docker.net9.org/library/python:3.11

ENV DEPLOY=1

WORKDIR /app

COPY . /app

RUN pip install -i https://pypi-cache-sepi.app.spring25a.secoder.net/simple -r requirements.txt

EXPOSE 80

CMD ["bash", "start.sh"]
# TODO End: [Student] Complete Dockerfile