FROM python:3.6-alpine
WORKDIR /app

ADD api_server.py /app
RUN pip install flask gunicorn

EXPOSE 8080
CMD [ "gunicorn", "-b", "0.0.0.0:8080", "api_server:app" ]
