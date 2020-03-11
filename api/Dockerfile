FROM python:alpine as requirements
WORKDIR /app
RUN pip install pipfile-requirements
COPY Pipfile* ./
RUN pipfile2req > requirements.txt

FROM python:3.7-alpine
WORKDIR /app
RUN mkdir nss
RUN apk add --no-cache --virtual build-dependencies build-base gcc musl-dev make
COPY --from=requirements /app/requirements.txt ./
RUN pip install -r requirements.txt
ADD api_server.py ./

EXPOSE 8080
CMD [ "uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8080" ]
