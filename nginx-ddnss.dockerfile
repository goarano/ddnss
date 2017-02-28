FROM nginx
RUN \
  apt-get update && \
  apt-get install -y make patch

ADD ./nss-ddnss /opt/ddnss
WORKDIR /opt/ddnss
RUN make install
