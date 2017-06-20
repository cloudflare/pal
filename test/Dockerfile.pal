FROM debian:latest

COPY test/verify-plaintext.sh /verify-plaintext.sh

VOLUME /var/run
VOLUME /testbin

CMD ["/testbin/pal", "-socket=/var/run/pald-rpc.sock", \
             "-socket.type=rpc", \
             "-env=demo", \
             "--", "/verify-plaintext.sh"]
