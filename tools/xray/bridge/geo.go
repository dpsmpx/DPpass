//go:build linux || windows

package bridge

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
)

// Геоданные для объяснения решений маршрутизации (D-09, D-27): попадает
// ли имя в geosite или адрес в geoip набора. Сопоставитель строит тот же
// код Xray, что и маршрутизатор ядра: разбор правила, как в
// infra/conf/router.go, домены — router.NewDomainMatcher, адреса —
// geodata.IPReg, как в router.NewIPMatcher. Файлы — из того же каталога
// (SetAssetDir), и фабрика сопоставителей — та же, что у ядра на этой
// платформе (на Android — компактная). Поэтому RouteEvaluator с таким
// GeoResolver не расходится с ядром ни в типах доменов (в dlc есть regexp,
// а у Go свой синтаксис), ни в сочетаниях атрибутов. Ядро для этого не
// запускается и не трогается. Факты о Xray, на которых это держится, —
// docs/research/BACKEND_STRATEGY.md, §7.
//
// Кеш моста — по каталогу: при смене каталога он сбрасывается, и код снова
// проверяется по файлам нового каталога — как ядро проверяет его при
// разборе конфигурации. Сами построенные сопоставители Xray держит по
// имени файла и коду, а не по каталогу (common/geodata, WeakCacheMap), пока
// на них есть ссылки, — и для ядра, и здесь. Поэтому набор — один на
// процесс: каталог задаёт AppGraph один раз при запуске, а новый набор
// приходит с новой версией приложения, то есть с новым процессом (D-27).

// GeoKind — вид кода. Числа — договор с engine.xray.GeoKind (Kotlin).
type GeoKind int

const (
	// GeoSite — geosite:код[@атрибут…]; значение — имя.
	GeoSite GeoKind = 1
	// GeoIP — geoip:код; значение — адрес, 4 или 16 байт.
	GeoIP GeoKind = 2
)

// geoCode — синтаксис кода, как у RoutingValidator (Kotlin). Двоеточия нет:
// код не выбирает другой файл («ext:файл:код»); «!» в начале нет: код не
// обращает условие.
var geoCode = regexp.MustCompile(`^[a-z0-9][a-z0-9_!@.-]{0,63}$`)

// geoCacheLimit — сколько сопоставителей держать: кодов в политике
// пользователя немного, а набор geosite одного кода бывает большим.
const geoCacheLimit = 64

type geoKey struct {
	kind GeoKind
	code string
}

type geoMatcher func(value []byte) bool

var (
	geoMu    sync.Mutex
	geoDir   string
	geoCache = map[geoKey]geoMatcher{}
)

// GeoMatch — попадает ли value в geosite:code (value — имя) или в
// geoip:code (value — адрес). Кода нет в наборе — KindConfig, как у
// Validate; атрибута или их сочетания нет — «не попадает», как у ядра
// (сочетания сверяет компилятор по оглавлению, D-27). Файла набора в
// каталоге нет (набор не перенёсся), неверный вид, код или адрес —
// KindContract: это не «такого кода нет».
func GeoMatch(kind GeoKind, code string, value []byte) (bool, error) {
	if !geoCode.MatchString(code) {
		return false, fail(KindContract, "%q — не код набора геоданных", code)
	}
	if kind == GeoIP && len(value) != net.IPv4len && len(value) != net.IPv6len {
		return false, fail(KindContract, "адрес — %d байт, ожидалось 4 или 16", len(value))
	}
	mu.Lock()
	dir := assets
	mu.Unlock()
	if dir == "" {
		return false, fail(KindContract, "каталог геоданных не задан (SetAssetDir)")
	}
	geoMu.Lock()
	defer geoMu.Unlock()
	if dir != geoDir || len(geoCache) >= geoCacheLimit {
		clear(geoCache)
		geoDir = dir
	}
	key := geoKey{kind, code}
	m, ok := geoCache[key]
	if !ok {
		file := geodata.DefaultGeoSiteDat
		if kind == GeoIP {
			file = geodata.DefaultGeoIPDat
		}
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			return false, fail(KindContract, "набора геоданных нет: %v", err)
		}
		var err error
		if m, err = buildGeoMatcher(kind, code); err != nil {
			return false, err
		}
		geoCache[key] = m
	}
	return m(value), nil
}

func buildGeoMatcher(kind GeoKind, code string) (geoMatcher, error) {
	switch kind {
	case GeoSite:
		rules, err := geodata.ParseDomainRules([]string{"geosite:" + code}, geodata.Domain_Substr)
		if err != nil {
			return nil, &Error{Kind: KindConfig, Err: err}
		}
		m, err := router.NewDomainMatcher(rules)
		if err != nil {
			return nil, &Error{Kind: KindConfig, Err: err}
		}
		// Пустое имя маршрутизатор не сопоставляет (DomainMatcher.Apply).
		return func(v []byte) bool { return len(v) > 0 && m.ApplyDomain(string(v)) }, nil
	case GeoIP:
		rules, err := geodata.ParseIPRules([]string{"geoip:" + code})
		if err != nil {
			return nil, &Error{Kind: KindConfig, Err: err}
		}
		m, err := geodata.IPReg.BuildIPMatcher(rules)
		if err != nil {
			return nil, &Error{Kind: KindConfig, Err: err}
		}
		// Как IPMatcher.Apply маршрутизатора для адреса назначения.
		return func(v []byte) bool { return m.AnyMatch([]net.IP{net.IP(v)}) }, nil
	default:
		return nil, fail(KindContract, "вид кода %d — ожидался geosite (%d) или geoip (%d)", kind, GeoSite, GeoIP)
	}
}
