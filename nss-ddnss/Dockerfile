FROM nginx
RUN \
  apt-get update && \
  apt-get install -y make patch

ADD . /opt/ddnss
WORKDIR /opt/ddnss
RUN make install
