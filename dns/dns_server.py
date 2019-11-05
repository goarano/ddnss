from dnslib.dns import DNSRecord, DNSQuestion, QTYPE, RR
from dnslib.server import DNSServer, DNSLogger, BaseResolver, DNSHandler
import requests as r


class DdnssResolver(BaseResolver):
    def __init__(self, upstream_address, upstream_port, zones, tll):
        self.upstream_address = upstream_address
        self.upstream_port = upstream_port
        self.zones = zones
        self.ttl = ttl

    def resolve(self, request: DNSRecord, handler: DNSHandler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        q: DNSQuestion
        for q in request.questions:
            for name, rtype, rr in self.zones:
                if qname.matchGlob(name) and (qtype in (rtype, 'ANY', 'CNAME')):
                    ip = self.ask_api_server(request)
                    if not ip:
                        continue
                    ttl = self.ttl
                    reply.add_answer(*RR.fromZone(f'{qname} {ttl} {qtype} {ip}'))

        if not reply.rr:
            use_tcp = handler.protocol != "udp"
            reply = DNSRecord.parse(request.send(self.upstream_address, self.upstream_port, tcp=use_tcp))
        return reply

    def ask_api_server(self, request: DNSRecord):
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        a = r.get(f"localhost:8080/{qname}")
        if a.ok:
            return a.text
        else:
            return None


def main():
    logger = DNSLogger(prefix=False)
    resolver = DdnssResolver("1.1.1.1", 53, ["test.ddnss"])
    server = DNSServer(resolver, port=8053, address="localhost", logger=logger, tcp=True)
    server.start()


if __name__ == '__main__':
    main()