FROM debian:latest

VOLUME /testbin
VOLUME /certs

EXPOSE 8080
CMD ["/testbin/redoctober", "-addr=0.0.0.0:8080", \
                    "-vaultpath=/tmp/diskrecord.json", \
                    "-certs=/certs/redoctober.pem", \
                    "-keys=/certs/redoctober-key.pem"]
