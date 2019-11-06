import ipaddress

from dnslib.dns import DNSRecord, QTYPE, RR
from dnslib.server import DNSServer, DNSLogger, BaseResolver, DNSHandler
import requests
from datetime import datetime

KEY_TIME = 'time'
KEY_VALUE = 'value'


class DdnssResolver(BaseResolver):
    def __init__(self, upstream_address, upstream_port, api_server, zones, ttl):
        self.upstream_address = upstream_address
        self.upstream_port = upstream_port
        self.api_server = api_server
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
        response = requests.get(f'http://{self.api_server}/{qname}', auth=('admin', 'secret'))
        if response.ok:
            return response.text
        else:
            return None


def main():
    logger = DNSLogger(prefix=False)
    resolver = DdnssResolver("1.1.1.1", 53, "localhost:8080", ["*.ddnss."], 10)
    server = DNSServer(resolver, port=8053, address="localhost", logger=logger, tcp=False)
    server.start()


if __name__ == '__main__':
    main()
