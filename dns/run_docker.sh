#!/usr/bin/env bash
docker build -t ddnss-$(basename $PWD) .
docker run --rm -it -p 5454:5353/udp --env-file .env --name ddnss-$(basename $PWD) ddnss-$(basename $PWD)
