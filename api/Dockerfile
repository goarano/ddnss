FROM python:3.6-alpine
WORKDIR /app

RUN pip install gunicorn
ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD api_server.py ./

EXPOSE 8080
CMD [ "gunicorn", "-b", "0.0.0.0:8080", "api_server:app" ]
