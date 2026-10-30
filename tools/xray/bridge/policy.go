//go:build linux || windows

package bridge

import (
	"fmt"
	"strings"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/tun"
)

// Службы, которые может запустить мост: то, что пишет компилятор DPpass
// (журнал, DNS, маршрутизация, политики, счётчики), и служебные части,
// которые Xray добавляет к любой конфигурации сам. Остального — API
// ядра (gRPC), метрик по HTTP, обратного прокси, наблюдателя с пробами,
// fakedns — нет: это входы или соединения, которых DPpass не заказывал.
var allowedApps = map[string]bool{
	"xray.app.log.Config":              true,
	"xray.app.dispatcher.Config":       true,
	"xray.app.proxyman.InboundConfig":  true,
	"xray.app.proxyman.OutboundConfig": true,
	"xray.app.router.Config":           true,
	"xray.app.dns.Config":              true,
	"xray.app.policy.Config":           true,
	"xray.app.stats.Config":            true,
}

const tunType = "xray.proxy.tun.Config"

// Вход раздачи туннеля другим устройствам (D-51): SOCKS (и HTTP на том же
// порту) с паролем, на частном IPv4-адресе интерфейса раздачи.
const (
	socksType      = "xray.proxy.socks.ServerConfig"
	shareTagPrefix = "dppass:share-" // XrayBackend.SHARE_TAG_PREFIX
	minSharePort   = 1024
)

// Локальный прокси подключения без VPN (D-95): SOCKS (и HTTP на том же
// порту) с паролем, только на 127.0.0.1 и только без входа TUN.
const localTag = "dppass:local" // XrayBackend.TAG_LOCAL

// tunInbound — вход TUN из собранной конфигурации (MTU — с умолчаниями Xray).
type tunInbound struct {
	MTU uint32
}

// checkPolicy проверяет собранную конфигурацию — ту самую protobuf,
// которую получит core.New, а не JSON: у JSON в Go имена полей
// сопоставляются без учёта регистра, и проверка текста пропустила бы
// `"Inbounds"`. Входов, кроме одного TUN, входов раздачи (SOCKS с паролем
// на частном IPv4, D-51) и локального прокси без TUN (SOCKS с паролем на
// 127.0.0.1, D-95), нет (T11): вход на порту без пароля был бы доступен
// любому приложению устройства.
func checkPolicy(cfg *core.Config) (*tunInbound, error) {
	for _, app := range cfg.App {
		if !allowedApps[app.Type] {
			return nil, fmt.Errorf("мост: служба %s не допускается (D-25)", app.Type)
		}
	}
	var found *tunInbound
	local := false
	for _, in := range cfg.Inbound {
		if in.ProxySettings == nil {
			return nil, fmt.Errorf("мост: вход %q без протокола", in.Tag)
		}
		t := in.ProxySettings.Type
		if t == socksType && strings.HasPrefix(in.Tag, shareTagPrefix) {
			if err := checkShareInbound(in); err != nil {
				return nil, err
			}
			continue
		}
		if t == socksType && in.Tag == localTag {
			if local {
				return nil, fmt.Errorf("мост: второй локальный прокси %q (D-95)", in.Tag)
			}
			if err := checkLocalInbound(in); err != nil {
				return nil, err
			}
			local = true
			continue
		}
		if t != tunType && !(testInbounds && testInboundAllowed(in)) {
			return nil, fmt.Errorf("мост: вход %q (%s) не допускается — входы ядра только TUN и раздача с паролем (T11, D-51)", in.Tag, t)
		}
		if t != tunType {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("мост: второй вход TUN %q", in.Tag)
		}
		msg, err := in.ProxySettings.GetInstance()
		if err != nil {
			return nil, err
		}
		tc, ok := msg.(*tun.Config)
		if !ok {
			return nil, fmt.Errorf("мост: вход %q: настройки не TUN", in.Tag)
		}
		found = &tunInbound{MTU: tc.MTU}
	}
	// Прокси — вместо VPN, а не рядом: при TUN приложение вне туннеля обошло бы через
	// него выбор приложений (D-38, D-95).
	if local && found != nil {
		return nil, fmt.Errorf("мост: локальный прокси %q вместе с TUN не допускается (D-95)", localTag)
	}
	return found, nil
}

// checkLocalInbound — локальный прокси (D-95, T11): только на 127.0.0.1, один
// порт от 1024, без транспортных надстроек, с логином и паролем.
func checkLocalInbound(in *core.InboundHandlerConfig) error {
	recv, err := receiver(in)
	if err != nil {
		return err
	}
	if recv.Listen == nil || recv.Listen.AsAddress().String() != "127.0.0.1" {
		return fmt.Errorf("мост: локальный прокси %q — только на 127.0.0.1 (D-95)", in.Tag)
	}
	return checkProxyInbound(in, recv, "локальный прокси")
}

// checkShareInbound — вход раздачи (D-51, T11): только с логином и паролем,
// только на частном IPv4-адресе (не 0.0.0.0, не loopback, не публичный) и
// с портом от 1024, без транспортных надстроек.
func checkShareInbound(in *core.InboundHandlerConfig) error {
	recv, err := receiver(in)
	if err != nil {
		return err
	}
	if recv.Listen == nil {
		return fmt.Errorf("мост: вход раздачи %q без адреса — слушал бы все интерфейсы (D-51)", in.Tag)
	}
	addr := recv.Listen.AsAddress()
	if !addr.Family().IsIPv4() || !addr.IP().IsPrivate() {
		return fmt.Errorf("мост: вход раздачи %q на %s — только частный IPv4 интерфейса раздачи (D-51)", in.Tag, addr)
	}
	return checkProxyInbound(in, recv, "вход раздачи")
}

func receiver(in *core.InboundHandlerConfig) (*proxyman.ReceiverConfig, error) {
	rs, err := in.ReceiverSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	recv, ok := rs.(*proxyman.ReceiverConfig)
	if !ok {
		return nil, fmt.Errorf("мост: вход %q без настроек приёма", in.Tag)
	}
	return recv, nil
}

// checkProxyInbound — общее у входа раздачи и локального прокси (T11): один
// порт от 1024, без транспортных надстроек, SOCKS с непустыми логином и паролем.
func checkProxyInbound(in *core.InboundHandlerConfig, recv *proxyman.ReceiverConfig, what string) error {
	if recv.PortList == nil || len(recv.PortList.Range) != 1 || recv.PortList.Range[0].From != recv.PortList.Range[0].To ||
		recv.PortList.Range[0].From < minSharePort {
		return fmt.Errorf("мост: %s %q — один порт от %d (T11)", what, in.Tag, minSharePort)
	}
	if recv.StreamSettings != nil && (recv.StreamSettings.SecurityType != "" || len(recv.StreamSettings.SecuritySettings) > 0) {
		return fmt.Errorf("мост: %s %q с надстройкой транспорта (T11)", what, in.Tag)
	}
	msg, err := in.ProxySettings.GetInstance()
	if err != nil {
		return err
	}
	sc, ok := msg.(*socks.ServerConfig)
	if !ok || sc.AuthType != socks.AuthType_PASSWORD || len(sc.Accounts) == 0 {
		return fmt.Errorf("мост: %s %q без пароля (T11)", what, in.Tag)
	}
	for user, pass := range sc.Accounts {
		if user == "" || pass == "" {
			return fmt.Errorf("мост: %s %q с пустым логином или паролем (T11)", what, in.Tag)
		}
	}
	return nil
}
