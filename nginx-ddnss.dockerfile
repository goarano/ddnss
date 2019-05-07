FROM nginx

RUN apt-get -yqq update && \
    apt-get -yqq install make patch gcc

ADD ./nss-ddnss /opt/ddnss

WORKDIR /opt/ddnss
RUN make install
