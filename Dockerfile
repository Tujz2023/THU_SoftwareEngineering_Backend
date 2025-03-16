# TODO Start: [Student] Complete Dockerfile
FROM docker.net9.org/library/python:3.11-bookworm

ENV DEPLOY=1

WORKDIR /app

COPY . /app/

RUN pip install -r requirements.txt -i https://pypi-cache-sepi.app.spring25a.secoder.net/simple/

EXPOSE 80

CMD ["./start.sh"]
# TODO End: [Student] Complete Dockerfile
