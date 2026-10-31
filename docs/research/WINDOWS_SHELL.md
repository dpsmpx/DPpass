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
- **Фильтр DNS и свои пробы** (31.10.2026, исходник Xray 26.9.30,
  `proxy/tun/tun_windows_wfp.go`). Разрешение «permit Xray» —
  жёсткое (сбрасывает право блокировать другим подслоям) и дано по
  образу процесса: `FwpmGetAppIdFromFileName0(os.Executable())`. Ядро
  DPpass — в процессе JVM, поэтому запросы имён проб DPpass мимо
  адаптера фильтр «dns» тоже пропускает (D-99).
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
- **Wine 9.0** (пакет Ubuntu `wine64`, 30.10.2026). В Wine прошли:
  - тесты моста для Windows (`go test -c` для `GOOS=windows`);
  - `java.exe` этого образа загрузил DLL моста и вызвал её функции JNI.
    Версия ядра — `26.9.30`, DPAPI шифрует и расшифровывает ключ.

  Адаптер Wintun и фильтры WFP Wine не даёт: их проверяет только ПК с
  Windows. Таблицу маршрутов тоже: `GetIPForwardTable2` в Wine 9.0
  отвечает «Request not supported» (проверено 30.10.2026 тестом моста).
  Ещё (31.10.2026, тесты моста): `GetAdaptersAddresses` (список
  интерфейсов Go) — «Request not supported»; `setsockopt` с
  `IP_UNICAST_IF` — `WSAEOPNOTSUPP`; сокет UDP Go не создаётся
  (`WSAIoctl` с `SIO_UDP_CONNRESET` — `WSAEOPNOTSUPP`); сокет IPv6 —
  `WSAEAFNOSUPPORT` (IPv6 нет в ядре машины). Привязку проб (D-99)
  тесты в Wine проверяют подменой опций, резолв — своим сервером по TCP.
  Планировщик в Wine 9.0 (31.10.2026): `schtasks /Create /XML` принимает
  задачу с `HighestAvailable`, `LogonTrigger` и `SecurityDescriptor` в
  `RegistrationInfo`, `/Run` и `/End` отвечают успехом, `/Delete`
  несуществующей задачи — код 1; поэтому тест установщика узнаёт, что
  задачу удалили. Запустить её как Windows и проверить список доступа
  Wine не может — это ПК автора.
- **Граф оболочки в Wine** (30.10.2026, оболочка 0.1.18-dev):
  - `jdeps` jar оболочки и её модулей называет модули `java.base`,
    `java.desktop`, `java.instrument`, `jdk.unsupported`;
  - в образе jlink из них `DesktopGraph.build` для Windows загрузил
    DLL моста, создал ключ данных под DPAPI (178 байт) и записал данные;
    новый граф в новом процессе их прочитал;
  - генератор `DRBG` JDK под Wine падает при засеве: перечисление
    сетевых интерфейсов (`NetworkInterface.getAll`) роняет процесс в
    `kernelbase.dll`. В прогоне первым ставился поставщик `SunMSCAPI`
    (модуль `jdk.crypto.mscapi`); на Windows это не нужно.
- **Права файлов в Wine** (30.10.2026, Wine 9.0). Права не хранятся:
  `GetNamedSecurityInfoW` для файлов на диске Linux отдаёт владельца
  `S-1-5-21-0-0-0-1000` и список доступа из прав Unix (SYSTEM и
  пользователь — полный доступ, Everyone — чтение).
  `SetNamedSecurityInfoW` отвечает успехом, но ничего не меняет — и в
  расширенные атрибуты файла не пишет. Проверку прав комплекта в Wine
  можно провести только по строкам SDDL; права NTFS — на Windows.
- **Комплект** (30–31.10.2026, оболочка 0.1.19-dev): архив zip — 53 МиБ,
  168 файлов. Рантайм jlink с `--strip-java-debug-attributes` и
  `--compress=zip-6` — модули `java.base`, `java.datatransfer`,
  `java.desktop`, `java.instrument`, `java.prefs`, `java.xml`,
  `jdk.unsupported`. `java.exe` этого рантайма под Wine прошёл
  самопроверку оболочки: ядро 26.9.30, DPAPI.
- **`jlink --strip-debug` на Linux меняет `.exe` Temurin** (31.10.2026,
  jlink 21.0.11 хоста, jmods 21.0.13): вместе с атрибутами классов он
  обрабатывает нативные команды. `java.exe`, `javaw.exe` и `keytool.exe`
  выходят на 10 КБ короче (без подписи Authenticode) и с новым
  заголовком в каждой сборке, DLL не меняются. С
  `--strip-java-debug-attributes` все 72 `.exe` и `.dll` рантайма
  побайтно совпадают с jmods, и две сборки комплекта дают одну сумму.

- **Тема приложений** (31.10.2026). Режим приложений по умолчанию
  («Параметры» → «Персонализация» → «Цвета») хранится у пользователя:
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`,
  DWORD `AppsUseLightTheme`, 1 — светлый, 0 — тёмный (ответ сотрудника
  Microsoft, https://learn.microsoft.com/en-us/answers/questions/41785/how-to-let-my-wpf-app-respond-to-default-app-mode).
  Описанный путь Microsoft — цвет `UISettings` WinRT
  (https://learn.microsoft.com/windows/apps/desktop/modernize/apply-windows-themes),
  из Go без WinRT его не достать; значение реестра читается
  `RegGetValueW`. В Wine 9.0 тест моста записал значение, прочитал его и
  вернул прежнее; что Windows меняет его при смене режима — ПК автора.
- **Значок `dppass.exe`** (31.10.2026). Преобразователя SVG в Python и
  JDK нет. Рисунок `dppass.svg` — круг, дуга и отрезок: его рисует
  `tools/desktop/app_icon.py` (покрытие пикселя по расстоянию до края) в
  ICO с записями PNG — их Windows читает с Vista. `windres` 2.41.90 (mingw-w64 Ubuntu) кладёт
  записи как есть, `objdump -p` видит `RT_ICON` (6 размеров) и
  `RT_GROUP_ICON`; две сборки дают одни байты.

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
- маршрут по умолчанию мимо адаптера от моста (`GetIPForwardTable2`);
- маршруты и DNS по `TunnelSpec`;
- что фильтр WFP `"dns"` не ломает подключение к серверу по имени;
- отсутствие утечки DNS и IPv6;
- уборка после отключения и после снятия процесса;
- тема окна по режиму приложений и всплывающее уведомление о пороге
  трафика из области уведомлений; значок `dppass.exe` в Проводнике;
- раздача с ПК (§7).

## 7. Раздача с ПК: общий доступ к подключению (ICS) — 31.10.2026

Повод — выбор автора в форме 31.10.2026: на Windows — «Раздача с ПК»
(D-101). Источники — заголовки и библиотеки mingw-w64 11.0.1 из Ubuntu,
документы Microsoft и проверка в облаке под Wine 9.0.

- **Что раздаёт ПК, знает ICS.** «Мобильный хот-спот» и общий доступ у
  адаптера делают адаптер частной стороной ICS. Объект COM
  `HNetCfg.HNetShare` (`CLSID_NetSharingManager`) с интерфейсом
  `INetSharingManager` перечисляет частные подключения
  (`get_EnumPrivateConnections`; `ICSSC_ENABLED` — только с включённым
  общим доступом) и даёт настройку каждого (`INetSharingConfiguration`:
  включено ли, сторона — `ICSSHARINGTYPE_PRIVATE`). GUID подключения —
  поле `guidId` из `INetConnection::GetProperties`; память свойств —
  `CoTaskMemFree`.
- **Порядок методов** — `netcon.h` и `oaidl.h` mingw-w64 11.0.1. GUID
  `CLSID_NetSharingManager`, `IID_INetSharingManager`,
  `IID_INetConnection` и `IID_IEnumVARIANT` в мосте
  (`tools/xray/bridge/share_windows.go`) сверены с байтами `libuuid.a`
  и `oaidl.h` того же пакета.
- **Регистрации из HKCU процессу с правами администратора не видны.** С
  Windows Vista COM процесса выше среднего уровня целостности не
  учитывает регистрации классов пользователя (HKCU) и берёт только
  регистрации ПК (HKLM): программа пользователя не подменит объект COM
  в процессе с правами. Источники: «COM activation change in Windows
  Vista» (блог Microsoft, learn.microsoft.com/archive/blogs/junfeng);
  Raymond Chen, «Not actually crossing the airtight hatchway: Applying
  per-user overrides» (devblogs.microsoft.com/oldnewthing). Исключение
  из доклада Virus Bulletin 2011 касается `SHCoCreateInstance` оболочки,
  а не `CoCreateInstance`.
- **Wine 9.0** (`9.0~repack-4build3`): `hnetcfg.dll` есть, но класса
  `NetSharingManager` в нём нет — `CoCreateInstance` отвечает
  `0x80040154` (`REGDB_E_CLASSNOTREG`). Проверено в облаке 31.10.2026.
  Перечисление в Wine проверяется только на поддельных объектах COM.
- **Не проверено** и остаётся ПК автора: виден ли «Мобильный хот-спот»
  частным подключением ICS, какой адрес у его адаптера, спрашивает ли
  брандмауэр Windows разрешение на вход и в какой сети оно нужно.
