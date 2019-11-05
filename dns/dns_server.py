import ipaddress

from dnslib.dns import DNSRecord, QTYPE, RR
from dnslib.server import DNSServer, DNSLogger, BaseResolver, DNSHandler
import requests as r
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
        self.zones = []
        for z in zones:
            self.zones.append((z[0], z[1], RR.))

    def resolve(self, request: DNSRecord, handler: DNSHandler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        print(f'{qtype} {qname}')
        for name, rtype, rr in self.zones:
            if qname.matchGlob(name) and (qtype in (rtype, 'ANY', 'CNAME')):
                answer = self.local_resolve(qname, qtype)
                if answer:
                    reply.add_answer(*answer)

        if not reply.rr:
            use_tcp = handler.protocol != "udp"
            reply = DNSRecord.parse(request.send(self.upstream_address, self.upstream_port, tcp=use_tcp))
        return reply

    def local_resolve(self, qname, qtype):
        now = datetime.utcnow()
        key = (qname, qtype)
        ip = None
        if key in self.cache and (now - self.cache[key][KEY_TIME]).total_seconds() <= self.ttl:
            ip = self.cache[key][KEY_VALUE]
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
        return RR.fromZone(f'{qname} {self.ttl} {qtype} {ip}')

    def ask_api_server(self, qname, qtype):
        a = r.get(f'{self.api_server}/{qname}')
        if a.ok:
            return a.text
        else:
            return None


def main():
    logger = DNSLogger(prefix=False)
    resolver = DdnssResolver("1.1.1.1", 53, "localhost:8080", [("test.ddnss", "A")], 10)
    server = DNSServer(resolver, port=53, address="localhost", logger=logger, tcp=False)
    server.start()


if __name__ == '__main__':
    main()