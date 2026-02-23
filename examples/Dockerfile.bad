FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y curl wget git
RUN pip install flask requests

ENV DB_PASSWORD=super_secret_123
ENV API_KEY=AKIA1234567890ABCDEF

ADD https://example.com/app.tar.gz /app/
COPY . .

CMD npm start

EXPOSE 3000
