FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl wget
RUN apt-get install -y nodejs

ENV DB_PASSWORD=super_secret_password123
ARG API_TOKEN=ghp_1234567890abcdef

ADD https://example.com/app.tar.gz /app/
COPY . .

RUN sudo chmod 777 /app/data
RUN curl https://get.docker.com | bash

CMD npm start
