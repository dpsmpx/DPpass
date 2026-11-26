#!/bin/sh
# D-120: запускать только в новом сетевом пространстве имён без uplink.
# На Linux: unshare -Urn sh tests/data/root/hotspot-route-guard.sh
set -eu

# Дополнительная проверка, не замена unshare. Android создаёт несколько
# встроенных туннельных интерфейсов даже в пустом пространстве.
export LC_ALL=C
links=$(ip -o link show)
unexpected=$(printf '%s\n' "$links" | awk '$2 !~ /^(lo|ip_vti0@NONE|ip6_vti0@NONE|sit0@NONE|ip6tnl0@NONE):$/ || $3 ~ /[<,]UP[,>]/')
if test -n "$unexpected" || test -z "$links"; then
    echo 'expected isolated network namespace' >&2
    exit 1
fi

ip link add dpguest type dummy
ip link add dpoutside type dummy
ip tuntap add dev dpgateway mode tun
for dev in dpguest dpoutside dpgateway; do ip link set "$dev" up; done
ip address add 192.0.2.1/24 dev dpguest
ip route add 198.51.100.0/24 dev dpoutside
ip -6 address add 2001:db8:1::1/64 dev dpguest nodad
ip -6 route add 2001:db8:2::/64 dev dpoutside
printf '1\n' > /proc/sys/net/ipv4/ip_forward
printf '1\n' > /proc/sys/net/ipv6/conf/all/forwarding

guest4() { ip route get 198.51.100.2 from 192.0.2.2 iif dpguest; }
guest6() { ip -6 route get 2001:db8:2::2 from 2001:db8:1::2 iif dpguest; }
expect_dev() {
    case "$2" in *" dev $1 "*|*" dev $1") ;; *) printf '%s\n' "$2" >&2; exit 1 ;; esac
}
expect_unreachable() {
    if result=$("$@" 2>&1); then
        # Старый iproute2 на Android успешно печатает отрицательный IPv6-маршрут.
        case "$result" in
            'unreachable '*" table 120 "*' error -113 '*|'unreachable '*' dev lo proto kernel '*' error -101 '*) return 0 ;;
        esac
    else
        case "$result" in *'No route to host'*|*'Network is unreachable'*) return 0 ;; esac
    fi
    printf 'unexpected guest route: %s\n' "$result" >&2
    exit 1
}

# Контроль: без защиты запросы с интерфейса гостя ушли бы в main.
expect_dev dpoutside "$(guest4)"
expect_dev dpoutside "$(guest6)"

# Терминальный unreachable не даёт RPDB продолжить поиск в main.
ip route add unreachable default metric 32767 table 120
ip -6 route add unreachable default metric 32767 table 120
# Устанавливаем оба терминальных правила до lookup и до допуска клиентов.
ip rule add iif dpguest priority 101 unreachable
ip -6 rule add iif dpguest priority 101 unreachable
expect_unreachable guest4
expect_unreachable guest6
ip rule add iif dpguest priority 100 lookup 120
ip -6 rule add iif dpguest priority 100 lookup 120
expect_unreachable guest4
expect_unreachable guest6
ip route add default dev dpgateway metric 100 table 120
expect_dev dpgateway "$(guest4)"
expect_unreachable guest6
# Адрес самого шлюза остаётся локальным: RPDB не изолирует DNS-службы
# телефона. Для них нужен отдельный входной фильтр или свой listener.
case "$(ip route get 192.0.2.1 from 192.0.2.2 iif dpguest)" in
    'local 192.0.2.1 '*) ;;
    *) echo 'expected local gateway delivery' >&2; exit 1 ;;
esac
expect_dev dpoutside "$(ip route get 198.51.100.2)"
expect_dev dpoutside "$(ip -6 route get 2001:db8:2::2)"

# Удаление TUN имитирует закрытие непостоянного TUN после смерти процесса.
ip link del dpgateway
expect_unreachable guest4
expect_unreachable guest6
expect_dev dpoutside "$(ip route get 198.51.100.2)"
expect_dev dpoutside "$(ip -6 route get 2001:db8:2::2)"
ip route del unreachable default metric 32767 table 120
ip -6 route del unreachable default metric 32767 table 120
expect_unreachable guest4
expect_unreachable guest6
expect_dev dpoutside "$(ip route get 198.51.100.2)"
expect_dev dpoutside "$(ip -6 route get 2001:db8:2::2)"
printf '%s\n' 'hotspot route guard: passed'
