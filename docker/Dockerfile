# Tracks the latest stable release; pass --build-arg to pin a version.
ARG SING_BOX_VERSION=latest

FROM ghcr.io/sagernet/sing-box:${SING_BOX_VERSION} AS singbox

FROM alpine:3.22

# grep/sed/gawk/coreutils replace the busybox applets ip.sh is written against.
RUN apk add --no-cache \
        bash curl jq bc netcat-openbsd bind-tools iproute2 \
        grep sed gawk coreutils ncurses ca-certificates tzdata python3

COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY ip.sh /opt/ipquality/ip.sh
COPY docker/link2singbox.py /opt/ipquality/link2singbox.py
COPY docker/entrypoint.sh /usr/local/bin/ipq
RUN chmod +x /usr/local/bin/ipq /opt/ipquality/link2singbox.py

ENV TERM=xterm LANG=C.UTF-8
ENTRYPOINT ["/usr/local/bin/ipq"]
