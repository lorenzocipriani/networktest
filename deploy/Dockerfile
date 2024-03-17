FROM golang:alpine AS telegraf-builder
WORKDIR /root
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache binutils git make \
    && git clone https://github.com/influxdata/telegraf.git \
    && cd /root/telegraf \
    && make build_tools \
    && ./tools/custom_builder/custom_builder \
    --config https://raw.githubusercontent.com/lorenzocipriani/networktest/main/deploy/telegraf.build.conf \
    && strip -s ./telegraf \
    && ./telegraf config create > ./telegraf.conf


FROM alpine:latest AS image-assembler
WORKDIR /root
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache bmon bpftool bpftrace ethtool htop iftop iperf3 iproute2 \
    iproute2-ss mtr net-tools procps-ng strace tcpdump zabbix-agent


FROM alpine:latest
WORKDIR /root
RUN mkdir -p /etc/telegraf && mkdir -p /etc/zabbix
# bmon
COPY --from=image-assembler /usr/bin/bmon /usr/bin/
# bpftool, ethtool
COPY --from=image-assembler /usr/sbin/*tool /usr/sbin/
# bpftrace
COPY --from=image-assembler /usr/bin/bpftrace* /usr/bin/
# htop
COPY --from=image-assembler /usr/bin/htop /usr/bin/
COPY --from=image-assembler /usr/share/applications/htop.desktop /usr/share/applications/
COPY --from=image-assembler /usr/share/icons/hicolor/128x128/apps/htop.png /usr/share/icons/hicolor/128x128/apps/
COPY --from=image-assembler /usr/share/icons/hicolor/scalable/apps/htop.svg /usr/share/icons/hicolor/scalable/apps/
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
# net-tools
COPY --from=image-assembler /bin/netstat /bin/
COPY --from=image-assembler /bin/route /bin/
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
# mtr, iftop, zabbix
COPY --from=image-assembler /usr/sbin/* /usr/sbin/
# zabbix
COPY --from=image-assembler /etc/zabbix/zabbix_agentd.conf /etc/zabbix/
# telegraf
COPY --from=telegraf-builder /root/telegraf/telegraf /usr/bin/telegraf
COPY --from=telegraf-builder /root/telegraf/telegraf.conf /etc/telegraf/
