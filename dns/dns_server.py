import os
import ipaddress
import logging
from dnslib.dns import DNSRecord, QTYPE, RR
from dnslib.server import DNSServer, DNSLogger, BaseResolver, DNSHandler
import requests
from datetime import datetime


DEBUG = os.environ.get('DEBUG')
SERVER_PORT = int(os.environ.get('SERVER_PORT', '5353'))
API_SERVER = os.environ.get('API_SERVER', 'localhost:8080')
API_SERVER_USERNAME = os.environ['API_SERVER_USERNAME']
API_SERVER_PASSWORD = os.environ['API_SERVER_PASSWORD']
UPSTREAM_ADDRESS = os.environ.get('UPSTREAM_ADDRESS', '1.1.1.1')
UPSTREAM_PORT = int(os.environ.get('UPSTREAM_PORT', '53'))
TTL = int(os.environ.get('TTL', '300'))
USE_TCP = bool(int(os.environ.get('USE_TCP', '0')))

KEY_TIME = 'time'
KEY_VALUE = 'value'


class DdnssResolver(BaseResolver):
    def __init__(self, upstream_address, upstream_port, api_server, api_server_username, api_server_password, zones, ttl):
        self.upstream_address = upstream_address
        self.upstream_port = upstream_port
        self.api_server = api_server
        self.api_server_username = api_server_username
        self.api_server_password = api_server_password
        self.ttl = ttl
        self.cache = {}
        self.zones = zones

    def resolve(self, request: DNSRecord, handler: DNSHandler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        # print(f'{qtype} {qname}')
        matched = False
        for name in self.zones:
            if qname.matchGlob(name):
                if qtype in ('A', 'AAAA', 'ANY', 'CNAME'):
                    answer = self.local_resolve(qname, qtype)
                    if answer:
                        reply.add_answer(*answer)
            matched = True

        if not matched:
            use_tcp = handler.protocol != "udp"
            reply = DNSRecord.parse(request.send(self.upstream_address, self.upstream_port, tcp=use_tcp))
        return reply

    def local_resolve(self, qname, qtype):
        now = datetime.utcnow()
        key = (qname, qtype)
        ip = None
        resp_ttl = self.ttl
        if key in self.cache:
            ttl_diff = (now - self.cache[key][KEY_TIME]).total_seconds()
            if ttl_diff <= self.ttl:
                ip = self.cache[key][KEY_VALUE]
                resp_ttl = int(self.ttl - ttl_diff)
        if not ip:
            try:
                ip = self.ask_api_server(qname, qtype)
                ipaddress.ip_address(ip)
                self.cache[key] = {
                    KEY_TIME: now,
                    KEY_VALUE: ip
                }
            except ValueError:
                return None
        return RR.fromZone(f'{qname} {resp_ttl} {qtype} {ip}')

    def ask_api_server(self, qname, qtype):
        response = requests.get(f'http://{self.api_server}/{qname}', auth=(self.api_server_username, self.api_server_password))
        if response.ok:
            return response.text
        else:
            return None


def main():
    if DEBUG:
        logging.basicConfig(level=logging.DEBUG)
    logger = DNSLogger(prefix=False)
    resolver = DdnssResolver(UPSTREAM_ADDRESS, UPSTREAM_PORT, API_SERVER, API_SERVER_USERNAME, API_SERVER_PASSWORD, ["*.ddnss."], TTL)
    server = DNSServer(resolver, port=int(SERVER_PORT), logger=logger, tcp=USE_TCP)
    print(f'running on 0.0.0.0:{SERVER_PORT}/{USE_TCP and "tcp" or "udp"}')
    server.start()


if __name__ == '__main__':
    main()
