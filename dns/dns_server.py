import ipaddress

from dnslib.dns import DNSRecord, QTYPE, RR
from dnslib.server import DNSServer, DNSLogger, BaseResolver, DNSHandler
import requests as r
from datetime import datetime


class DdnssResolver(BaseResolver):
    def __init__(self, upstream_address, upstream_port, zones, ttl):
        self.upstream_address = upstream_address
        self.upstream_port = upstream_port
        self.zones = zones
        self.ttl = ttl
        self.cache = {}

    def resolve(self, request: DNSRecord, handler: DNSHandler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name, rtype, rr in self.zones:
            if qname.matchGlob(name) and (qtype in (rtype, 'ANY', 'CNAME')):
                a = self.local_resolve(qname, qtype)
                if a:
                    reply.add_answer(*a)

        if not reply.rr:
            use_tcp = handler.protocol != "udp"
            reply = DNSRecord.parse(request.send(self.upstream_address, self.upstream_port, tcp=use_tcp))
        return reply

    def local_resolve(self, qname, qtype):
        now = datetime.utcnow()
        key = (qname, qtype)
        ip = None
        if key in self.cache and (now - self.cache[key]['time']).total_seconds() > self.ttl:
            ip = self.cache[key]['value']
        if not ip:
            try:
                ip = self.ask_api_server(qname, qtype)
                ipaddress.ip_address(ip)
                self.cache[key] = {
                    'time': now,
                    'value': ip
                }
            except ValueError:
                return None
        return RR.fromZone(f'{qname} {self.ttl} {qtype} {ip}')

    def ask_api_server(self, qname, qtype):
        a = r.get(f"localhost:8080/{qname}")
        if a.ok:
            return a.text
        else:
            return None


def main():
    logger = DNSLogger(prefix=False)
    resolver = DdnssResolver("1.1.1.1", 53, ["test.ddnss"], 10)
    server = DNSServer(resolver, port=8053, address="localhost", logger=logger, tcp=True)
    server.start()


if __name__ == '__main__':
    main()