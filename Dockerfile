FROM python:3.6-alpine
WORKDIR /app

ADD server.py /app
RUN pip install flask gunicorn

EXPOSE 5000
CMD [ "gunicorn", "-b", "0.0.0.0:5000", "server:app" ]
