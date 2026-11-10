FROM alpine:3.20

RUN apk add --no-cache bash iproute2 iptables openresolv ca-certificates procps

COPY amneziawg-go /usr/local/bin/amneziawg-go
COPY awg /usr/local/bin/awg
COPY awg-quick /usr/local/bin/awg-quick
RUN chmod +x /usr/local/bin/amneziawg-go /usr/local/bin/awg /usr/local/bin/awg-quick && \
    ln -sf /usr/local/bin/awg /usr/local/bin/wg

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
