#!/usr/bin/env bash
docker build -t ddnss-$(basename $PWD) .
docker run --rm -it -p 8080:8080 --env-file .env -v $PWD/config.yaml:/app/config.yaml:ro --name ddnss-$(basename $PWD) ddnss-$(basename $PWD)
