# Оболочка Windows: вход TUN Xray, Wintun, сборка с Linux

Дата исследования: **30 октября 2026**. Повод — выбор автора в форме
сессии 30.10.2026: оболочка для Windows «сразу с VPN (Wintun)», мост
ядра — «mingw-w64 из Ubuntu», Java — «в комплекте». Документ — факты
для решения D-97; само устройство оболочки — в решении. Источники —
исходники закреплённой версии Xray и её зависимостей в кеше модулей Go,
страницы поставщиков и проверка в облачной сессии; чужой код не
берётся (`docs/direction/RESEARCH_SCOPE.md`, §3, правило 5; D-20).

## 1. Коротко

- **Систему настраивает само ядро.** Вход TUN Xray 26.9.30 на Windows
  сам создаёт адаптер Wintun и ставит ему адреса, маршруты, MTU и DNS,
  а по просьбе — фильтры WFP против утечки DNS и чужой версии IP (§2).
  Готовый дескриптор, как на Android и Linux (D-25, D-74), он не
  принимает. Оболочке не нужны ни `route`, ни `netsh`.
- **Петлю закрывает привязка к интерфейсу.** С `autoOutboundsInterface`
  ядро привязывает свои сокеты к физическому интерфейсу
  (`IP_UNICAST_IF`), а имена серверов при фильтре DNS резолвит само.
  Каждый запуск добавляет в глобальный список Xray ещё один хук сокетов
  и не убирает его (§2.4).
- **Wintun 0.14.1** — подписанные DLL с лицензией, которая разрешает
  класть их рядом с программой, если та обращается к DLL только через
  API `wintun.h`. Xray так и делает (§3).
- **Сборка с Linux проверена в облаке** (§4):
  - DLL с ядром Xray собирает mingw-w64 13.2 из Ubuntu за 35 с;
  - рантайм Java для Windows собирает `jlink` хоста из jmods Temurin
    21.0.13.
- **Права администратора нужны** и Wintun, и WFP. Отдельной возможности
  вроде `CAP_NET_ADMIN` на Windows нет (§5).

## 2. Вход TUN Xray на Windows

Xray 26.9.30 (модуль `github.com/xtls/xray-core`
`v1.260327.1-0.20260930074004-b26a91de4f32`, D-24): `proxy/tun/tun_windows.go`,
`tun_windows_wfp.go`, `handler.go`, `config.go`, `README.md`.

### 2.1 Адаптер

- `NewTun` открывает адаптер Wintun с именем из `name` или создаёт его.
  GUID адаптера выводится из MD5 имени, так что адаптер с тем же именем
  переиспользуется. Сессия — с кольцом 8 МиБ.
- Адаптер существует, пока работает ядро: README, «WINDOWS SUPPORT» —
  «exist while Xray is running».
- `desc` — тип туннеля адаптера, по умолчанию `Wintun`.

### 2.2 Адреса, маршруты, DNS

`Start` делает следующее, по порядку:
1. Адреса из `gateway` — `SetIPAddressesForFamily`.
2. Маршруты из `autoSystemRoutingTable` — `SetRoutesForFamily`, с нулевым
   шлюзом и метрикой 0.
3. У интерфейса той версии IP, у которой есть маршруты, — метрика 0 без
   автоматической метрики и MTU из `MTU`. Обнаружение маршрутизаторов
   выключено.
4. DNS адаптера из `DNS` — `SetDNS`. Регистрацию адресов в DNS ядро
   выключает, кеш DNS сбрасывает при запуске и остановке.

Ошибка «интерфейс ещё не найден» повторяется до 15 раз с паузой в
секунду. Исключающих маршрутов нет: обойти туннель можно только
маршрутами, которых нет в списке.

### 2.3 Фильтры WFP (`autoSystemWfpBlockLeak`)

Работают только вместе с `autoSystemRoutingTable`.
- **`"dns"`** (нужен `DNS`): порт 53 любой программы, кроме самого
  ядра, — только через TUN. Причина в README: Windows шлёт запросы имён
  и DNS-серверам других интерфейсов, мимо маршрутов. Серверы `DNS`
  должны лежать в `gateway` или в маршрутах, иначе запросы к ним
  блокируются (предупреждение в журнале).
- **`"misconfigtun"`**: версия IP без маршрутов в TUN блокируется
  целиком, кроме loopback и служебного на канале (DHCP, ND, MLD).
- **Отказ.** Если фильтры не встали, ядро не запускается: «Rather no TUN
  than a leaking one». Снимаются они при выходе ядра.
- **Чего фильтры не закрывают:** LLMNR, mDNS и NetBIOS (README). Ломают
  они локальный резолвер на `127.0.0.1:53`, DNS другого VPN, NAT
  виртуальных машин и вход в captive portal.

### 2.4 Свои сокеты ядра

- `autoOutboundsInterface` (`"auto"` — по таблице маршрутов) включает
  `InterfaceUpdater`. Ядро выбирает интерфейс с маршрутом по умолчанию и
  наименьшей метрикой, кроме самого TUN; при наличии Wi-Fi — Wi-Fi.
- Через `internet.RegisterDialerController` ядро ставит хук: каждый
  исходящий сокет, кроме loopback, привязывается к этому интерфейсу
  (`IP_UNICAST_IF`, `IPV6_UNICAST_IF`). Это замена `protect()` Android и
  метки `SO_MARK` Linux (D-25, D-74).
- При смене маршрутов и интерфейсов (колбэки `winipcfg`) интерфейс
  выбирается заново.
- **Хук копится.** `RegisterDialerController` дописывает функцию в
  глобальный срез `internet.Controllers` (`transport/internet/system_dialer.go`),
  и способа снять её Xray не даёт. Каждый `Handler.Start` с
  `autoOutboundsInterface` добавляет ещё одну. Оркестратор запускает
  ядро по кандидатам плана и при переподключении (D-15), поэтому за
  сеанс хуки множатся. Мост на Linux ставит свой хук один раз на процесс
  (`tools/xray/bridge/protect.go`). На Windows длину среза нужно
  запоминать до запуска и возвращать после остановки — срез и его
  блокировка (`ControllersLock`) экспортированы.
- **Имена серверов.** Пока DNS ограничен фильтром и действует
  `autoOutboundsInterface`, ядро резолвит имена серверов само — своими
  запросами к DNS-серверам других интерфейсов, мимо кеша Windows
  (`resolveOnOwn`, README). Иначе запрос системы ушёл бы в TUN — к ядру,
  которое ещё не подключилось.

### 2.5 `wintun.dll`

Go-пакет `golang.zx2c4.com/wintun` (`v0.0.0-20230126152724-0fa3db229ce2`,
MIT) загружает DLL лениво: `LoadLibraryEx("wintun.dll",
LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`
(`dll.go`). Каталог приложения здесь — каталог исполняемого файла
процесса. У JVM это `bin\` рантайма, где лежит `javaw.exe`, а не каталог
нашей DLL моста.

## 3. Wintun

Страница `www.wintun.net`, 30.10.2026:
- драйвер с исходниками под GPL-2.0;
- «the below signed DLLs are the only supported way of distributing
  Wintun»;
- версия 0.14.1, `wintun-0.14.1.zip`, SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.

Архив скачан 30.10.2026, сумма совпала. Внутри:
- `bin/amd64/wintun.dll` — 427 552 байта, от 17.10.2021; там же DLL для
  arm, arm64 и x86;
- `include/wintun.h`;
- `LICENSE.txt` — «Prebuilt Binaries License» WireGuard LLC.

По лицензии:
- запрещено изменять и разбирать DLL и удалять из неё уведомления;
- распространять можно без согласия WireGuard LLC, «insofar as the
  Software is distributed alongside other software that uses the Software
  only via the Permitted API» — API `wintun.h`;
- имя WireGuard и Wintun нельзя использовать для продвижения.

Xray обращается к DLL только через экспорт `wintun.h` (`wintun.go`).

## 4. Сборка с Linux — проверено 30.10.2026 в облаке

- **mingw-w64.** Пакеты Ubuntu `gcc-mingw-w64-x86-64-posix` и
  `binutils-mingw-w64-x86-64` 13.2.0-6ubuntu1+26.1.
  - Пробная DLL `-buildmode=c-shared`: `GOOS=windows`, `GOARCH=amd64`,
    `CGO_ENABLED=1`, `CC=x86_64-w64-mingw32-gcc`, импорт
    `main/distro/all`, одна экспортная функция.
  - Собрана тулчейном Go проекта за 35 с, 63 МиБ.
  - Импортирует только `KERNEL32.dll` и `msvcrt.dll`: библиотеки
    mingw рядом не нужны. Экспорт `objdump -p` видит.
- **Модули Go.** Для Windows в сборку входят `golang.zx2c4.com/wintun` и
  `golang.zx2c4.com/wireguard/windows` v1.1.1 (`winipcfg`, MIT). Обе уже
  есть в `tools/xray/go.sum`; в сборки Android и Linux они не попадают.
- **Temurin.** Ответ `api.adoptium.net`, 30.10.2026:
  - последний JDK 21 для Windows x64 — 21.0.13+9 (`JAVA_VERSION_DATE`
    2026-10-20);
  - `OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip`, 205 421 281
    байт, SHA-256
    `a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9`.

  Архив скачан, сумма совпала. Внутри есть `jmods/`,
  `include/win32/jni_md.h` и `legal/` (лицензия GPL-2.0 с Classpath
  Exception и уведомления компонентов).
- **jlink.** `jlink` хоста (OpenJDK 21.0.11) собрал из jmods Temurin
  21.0.13 образ Windows `java.base,java.desktop`, 75 МиБ:
  - в `bin\` — `java.exe`, `javaw.exe`, `awt.dll` и рантайм MSVC из
    состава Temurin;
  - в `release` — `JAVA_VERSION="21.0.13"`.

  Окна и запуска на Windows в облаке нет: проверено только, что образ
  собирается.

## 5. Права

- Создать адаптер Wintun и поставить фильтры WFP может только процесс с
  правами администратора. Аналога одной возможности `CAP_NET_ADMIN`
  Linux (D-74) у Windows нет.
- Просить права при запуске умеет исполняемый файл с манифестом
  `requestedExecutionLevel level="requireAdministrator"`: UAC спросит
  при каждом запуске. Скрипт `.cmd` такого манифеста не несёт.
- Ресурс манифеста `windres` из mingw-w64 вшивает в маленький
  запускатель на C. Тот запускает `javaw.exe` рантайма с jar оболочки.

## 6. Что осталось проверить на ПК с Windows

Облако Windows не запускает, поэтому на ПК автора:
- окно и запрос UAC;
- создание адаптера `dppass0`;
- маршруты и DNS по `TunnelSpec`;
- что фильтр WFP `"dns"` не ломает подключение к серверу по имени;
- отсутствие утечки DNS и IPv6;
- уборка после отключения и после снятия процесса.
