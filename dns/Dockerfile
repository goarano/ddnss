FROM python:3.6-alpine
WORKDIR /app

ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD dns_server.py ./

EXPOSE 5353/udp
CMD [ "python", "dns_server.py" ]
