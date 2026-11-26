#!/bin/sh
# D-120: только в новом сетевом пространстве имён: unshare -n sh ...
set -eu
links=$(ip -o link show)
unexpected=$(printf '%s\n' "$links" | awk '$2 !~ /^(lo|ip_vti0@NONE|ip6_vti0@NONE|sit0@NONE|ip6tnl0@NONE):$/ || $3 ~ /[<,]UP[,>]/')
test -n "$links" && test -z "$unexpected" || exit 1
ip link add dpguest type dummy

# Сначала закрываем IPv4/IPv6 целиком, затем открываем только DHCPv4.
# DNS телефона не разрешён: DNS обработчик ещё не подключён.
iptables -t filter -I INPUT 1 -i dpguest -j DROP
ip6tables -t filter -I INPUT 1 -i dpguest -j DROP
iptables -t filter -I INPUT 1 -i dpguest -p udp --sport 68 --dport 67 -j ACCEPT

v4=$(iptables -t filter -S INPUT)
v6=$(ip6tables -t filter -S INPUT)
test "$v4" = '-P INPUT ACCEPT
-A INPUT -i dpguest -p udp -m udp --sport 68 --dport 67 -j ACCEPT
-A INPUT -i dpguest -j DROP'
test "$v6" = '-P INPUT ACCEPT
-A INPUT -i dpguest -j DROP'
printf '%s\n' 'hotspot input guard rules: passed'

# Проверяем также реальное применение INPUT на loopback: ядро Zenfone
# не создаёт veth. Это не имитация входного интерфейса Wi-Fi.
ip link set lo up
ping -c 1 -W 1 127.0.0.1 >/dev/null
iptables -t filter -I INPUT 1 -i lo -p icmp -j DROP
if ping -c 1 -W 1 127.0.0.1 >/dev/null; then
    echo 'INPUT unexpectedly allowed ICMP' >&2
    exit 1
fi
iptables -t filter -L INPUT -n -v -x | awk '
    $3 == "DROP" && $4 == "icmp" && $6 == "lo" && $1 > 0 { matched = 1 }
    END { exit !matched }
'
printf '%s\n' 'hotspot input guard packet smoke: passed'
