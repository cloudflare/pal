FROM debian:latest

COPY test/config.yaml /config.yaml

VOLUME /var/run
VOLUME /testbin
VOLUME /certs

CMD ["/testbin/pald", "-addr.rpc=unix:///var/run/pald-rpc.sock", \
              "-config=/config.yaml", \
              "-env=demo"]
