FROM python:alpine as requirements
WORKDIR /app
RUN pip install pipfile-requirements
COPY Pipfile* ./
RUN pipfile2req > requirements.txt

FROM python:3.7-alpine
WORKDIR /app
COPY --from=requirements /app/requirements.txt ./
RUN pip install -r requirements.txt
ADD dns_server.py ./

EXPOSE 5353/udp
CMD [ "python", "dns_server.py" ]
