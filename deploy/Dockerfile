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
# alpine updates
COPY --from=image-assembler /bin/busybox /bin/
COPY --from=image-assembler /sbin/apk /sbin/
COPY --from=image-assembler /sbin/ldconfig /sbin/
# bmon
COPY --from=image-assembler /usr/bin/bmon /usr/bin/
COPY --from=image-assembler /usr/lib/libncursesw.so.6 /usr/lib/
COPY --from=image-assembler /usr/lib/libconfuse.so.2 /usr/lib/
COPY --from=image-assembler /usr/lib/libnl-3.so.200 /usr/lib
COPY --from=image-assembler /usr/lib/libnl-route-3.so.200 /usr/lib/
# bpftool, ethtool
COPY --from=image-assembler /usr/sbin/*tool /usr/sbin/
COPY --from=image-assembler /usr/lib/libelf.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libcap.so.2 /usr/lib/
COPY --from=image-assembler /usr/lib/libbfd-2.41.so /usr/lib/
COPY --from=image-assembler /usr/lib/libopcodes-2.41.so /usr/lib/
COPY --from=image-assembler /usr/lib/libzstd.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libsframe.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libmnl.so.0 /usr/lib/
# bpftrace
COPY --from=image-assembler /usr/bin/bpftrace* /usr/bin/
COPY --from=image-assembler /usr/lib/libbpf.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libbcc_bpf.so.0 /usr/lib/
COPY --from=image-assembler /usr/lib/libdw.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libclang.so.17 /usr/lib/
COPY --from=image-assembler /usr/lib/libLLVM-17.so /usr/lib/
COPY --from=image-assembler /usr/lib/libstdc++.so.6 /usr/lib/
COPY --from=image-assembler /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/liblzma.so.5 /usr/lib/
COPY --from=image-assembler /usr/lib/libfts.so.0 /usr/lib/
COPY --from=image-assembler /usr/lib/libbz2.so.1 /usr/lib/
COPY --from=image-assembler /usr/lib/libffi.so.8 /usr/lib/
COPY --from=image-assembler /usr/lib/libxml2.so.2 /usr/lib/
# htop
COPY --from=image-assembler /usr/bin/htop /usr/bin/
COPY --from=image-assembler /usr/share/applications/htop.desktop /usr/share/applications/
COPY --from=image-assembler /usr/share/icons/hicolor/128x128/apps/htop.png /usr/share/icons/hicolor/128x128/apps/
COPY --from=image-assembler /usr/share/icons/hicolor/scalable/apps/htop.svg /usr/share/icons/hicolor/scalable/apps/
# iftop
COPY --from=image-assembler /usr/sbin/iftop /usr/sbin/
# iperf3
COPY --from=image-assembler /usr/bin/iperf3 /usr/bin/
COPY --from=image-assembler /usr/lib/libiperf* /usr/lib/
# iproute2
COPY --from=image-assembler /sbin/bridge /sbin/
COPY --from=image-assembler /sbin/ctstat /sbin/
COPY --from=image-assembler /sbin/genl /sbin/
COPY --from=image-assembler /sbin/ifstat /sbin/
COPY --from=image-assembler /sbin/lnstat /sbin/
COPY --from=image-assembler /sbin/nstat /sbin/
COPY --from=image-assembler /sbin/routel /sbin/
COPY --from=image-assembler /sbin/rtacct /sbin/
COPY --from=image-assembler /sbin/rtmon /sbin/
COPY --from=image-assembler /sbin/rtstat /sbin/
# mtr
COPY --from=image-assembler /usr/sbin/mtr* /usr/sbin/
COPY --from=image-assembler /usr/lib/libjansson.so.4 /usr/lib/
# net-tools
COPY --from=image-assembler /bin/netstat /bin/
COPY --from=image-assembler /sbin/ipmaddr /sbin/
COPY --from=image-assembler /sbin/plipconfig /sbin/
COPY --from=image-assembler /sbin/rarp /sbin/
# procps-ng
COPY --from=image-assembler /bin/slabtop /bin/
COPY --from=image-assembler /bin/vmstat /bin/
COPY --from=image-assembler /bin/w /bin/
# strace
COPY --from=image-assembler /usr/bin/strace* /usr/bin/
# tcpdump
COPY --from=image-assembler /usr/bin/tcpdump /usr/bin/
COPY --from=image-assembler /usr/lib/libpcap.so.1 /usr/lib/ 
# zabbix
COPY --from=image-assembler /usr/sbin/zabbix_agentd /usr/sbin/
COPY --from=image-assembler /etc/zabbix/zabbix_agentd.conf /etc/zabbix/
# telegraf
COPY --from=image-assembler /root/telegraf/telegraf /usr/bin/telegraf
COPY --from=image-assembler /root/telegraf/telegraf.conf /etc/telegraf/

LABEL org.opencontainers.image.source=https://github.com/lorenzocipriani/networktest
LABEL org.opencontainers.image.description="NetworkTest - Container image for testing Kubernetes pod communication"
LABEL org.opencontainers.image.licenses=MIT