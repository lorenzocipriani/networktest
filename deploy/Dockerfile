FROM golang:alpine AS image-assembler
WORKDIR /root
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache bmon bpftool bpftrace ethtool htop iftop iperf3 iproute2 \
    iproute2-ss mtr net-tools procps-ng strace tcpdump zabbix-agent \
    binutils git make \
    && strip -s /lib/ld-musl-x86_64.so.1 \
    && strip -s /lib/libcrypto.so.3 \
    && strip -s /lib/libssl.so.3 \
    && strip -s /usr/bin/bpftrace \
    && strip -s /usr/bin/bpftrace-aotrt \
    && strip -s /usr/bin/strace \
    && strip -s /usr/bin/tcpdump \
    && strip -s /usr/sbin/bpftool \
    && strip -s /usr/sbin/ethtool \
    && strip -s /usr/sbin/zabbix_agentd \
    && git clone https://github.com/influxdata/telegraf.git \
    && cd /root/telegraf \
    && make build_tools \
    && ./tools/custom_builder/custom_builder \
    --config https://raw.githubusercontent.com/lorenzocipriani/networktest/main/deploy/telegraf.build.conf \
    && strip -s ./telegraf \
    && ./telegraf config create > ./telegraf.conf


FROM alpine:latest
WORKDIR /
RUN mkdir -p /etc/telegraf && mkdir -p /etc/zabbix
# alpine updates & /bin executables
COPY --from=image-assembler /bin/busybox \
    # net-tools
    /bin/netstat \
    # procps-ng
    /bin/slabtop \
    /bin/vmstat \
    /bin/w \
    #
    /bin/

    COPY --from=image-assembler \
    /sbin/apk \
    /sbin/ldconfig \
    /sbin/

# /usr/bin executables
COPY --from=image-assembler \
    # bmon
    /usr/bin/bmon \
    # htop
    /usr/bin/htop \
    # iperf3
    /usr/bin/iperf3 \
    # strace
    /usr/bin/strace* \
    # tcpdump
    /usr/bin/tcpdump \
    # telegraf
    /root/telegraf/telegraf \
    /usr/bin/

# /usr/sbin executables
COPY --from=image-assembler \
    # bpftool, ethtool
    /usr/sbin/*tool \
    # iftop
    /usr/sbin/iftop \
    # mtr
    /usr/sbin/mtr* \
    # net-tools
    /sbin/ipmaddr \
    /sbin/plipconfig \
    /sbin/rarp \

    /usr/sbin/

# /sbin executables
COPY --from=image-assembler \
    # iproute2
    /sbin/bridge \
    /sbin/ctstat \
    /sbin/genl \
    /sbin/ifstat \
    /sbin/lnstat \
    /sbin/nstat \
    /sbin/routel \
    /sbin/rtacct \
    /sbin/rtmon \
    /sbin/rtstat \
    #
    /sbin/

# Shared libraries in /lib
COPY --from=image-assembler \
    # procps-ng
    /lib/libproc2.so.0 \
    /lib/

# Shared libraries in /usr/lib
COPY --from=image-assembler \
    # bpftool, ethtool
    /usr/lib/libelf.so.1 \
    /usr/lib/libcap.so.2 \
    /usr/lib/libbfd-2.41.so \
    /usr/lib/libopcodes-2.41.so \
    /usr/lib/libzstd.so.1 \
    /usr/lib/libsframe.so.1 \
    /usr/lib/libmnl.so.0 \
    # bmon
    /usr/lib/libncursesw.so.6 \
    /usr/lib/libconfuse.so.2 \
    /usr/lib/libnl-3.so.200 \
    /usr/lib/libnl-route-3.so.200 \
    # iperf3
    /usr/lib/libiperf* \
    # mtr
    /usr/lib/libjansson.so.4 \
    # /usr/lib/libncursesw.so.6 \
    # procps-ng
    # /usr/lib/libncursesw.so.6 \
    /usr/lib/libintl.so.8 \
    # strace
    /usr/lib/libdw.so.1 \
    # /usr/lib/libelf.so. \
    /lib/libz.so.1 \
    /usr/lib/libfts.so.0 \
    # /usr/lib/libzstd.so.1 \
    /usr/lib/liblzma.so.5 \
    /usr/lib/libbz2.so.1 \
    # tcpdump
    /usr/lib/libpcap.so.1 \
    /usr/lib/

# htop extra
COPY --from=image-assembler /usr/share/applications/htop.desktop /usr/share/applications/
COPY --from=image-assembler /usr/share/icons/hicolor/128x128/apps/htop.png /usr/share/icons/hicolor/128x128/apps/
COPY --from=image-assembler /usr/share/icons/hicolor/scalable/apps/htop.svg /usr/share/icons/hicolor/scalable/apps/

# telegraf conf
COPY --from=image-assembler /root/telegraf/telegraf.conf /etc/telegraf/

LABEL org.opencontainers.image.source=https://github.com/lorenzocipriani/networktest
LABEL org.opencontainers.image.description="NetworkTest - Container image for testing Kubernetes pod communication"
LABEL org.opencontainers.image.licenses=MIT