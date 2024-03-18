# networktest
Container image for testing Kubernetes pod communication

This image is based on latest Alpine, then it adds the following packages:
- [bmon](https://github.com/tgraf/bmon)
- [bpftool](https://github.com/libbpf/bpftool), 
  [bpftrace](https://github.com/bpftrace/bpftrace)
- [ethtool](https://linux.die.net/man/8/ethtool)
- [htop](https://htop.dev/), [iftop](https://linux.die.net/man/8/iftop)
- [iperf3](https://iperf.fr/)
- [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) \
  all but route
- [mtr](https://linux.die.net/man/8/mtr)
- [net-tools](https://wiki.linuxfoundation.org/networking/net-tools)
- [procps-ng](https://gitlab.com/procps-ng/procps), just:
  - slabtop
  - vmstat
  - w
- [strace](https://linux.die.net/man/1/strace)
- [tcpdump](https://www.tcpdump.org/)
- [telegraf](https://www.influxdata.com/time-series-platform/telegraf/) \
  This is a reduced version to limit the size of the executable, see the list of
  the included plugins looking at the 
  [telegraf.build.conf](deploy/telegraf.build.conf) file
- [zabbix-agent](https://www.zabbix.com/)