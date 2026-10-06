# AntiBlock

AntiBlock is a DNS-based dynamic routing tool for Linux and OpenWrt. It watches DNS responses for selected domain lists, extracts returned IPv4 addresses, and dynamically installs routes for those addresses through configured network interfaces.

Domain lists can be read from local files or downloaded from HTTP(S) URLs. A single AntiBlock process can maintain several domain-list-to-interface mappings. CNAME targets and HTTPS AliasMode targets (`TYPE 65`, `SvcPriority=0`) discovered in DNS responses inherit the routing rule of the matched domain, so later A answers for the learned target can be routed as well.

AntiBlock 3.0.0 keeps the project intentionally small: GNU99, libpcap, libcurl, the original array-backed hashmap, a single-threaded event loop, and direct interaction with the Linux routing table. It supports both L3 interfaces and Ethernet/L2 interfaces with a default gateway, tracks route lifetime using DNS TTL, and includes Docker end-to-end integration tests.

## Описание

AntiBlock - инструмент динамической маршрутизации для Linux и OpenWrt, работающий на основе DNS. Он отслеживает DNS-ответы для выбранных списков доменов, извлекает полученные IPv4-адреса и добавляет маршруты к этим адресам через настроенные сетевые интерфейсы.

Списки доменов можно читать из локальных файлов или загружать по HTTP(S). Один процесс может одновременно поддерживать несколько соответствий между списками доменов и интерфейсами. Дополнительный список подсетей позволяет исключить выбранные IPv4-сети из динамической маршрутизации.

Списки обычно обновляются раз в 24 часа. При ошибке загрузки HTTP(S)-источника повтор выполняется через 5 минут; после успешного обновления возвращается обычный интервал. Старая таблица освобождается перед загрузкой новой, чтобы не хранить два больших набора доменов одновременно.

AntiBlock не является DNS-фильтром, прокси или полноценным VPN/PBR-фреймворком. Его задача проще: связать знания из DNS с обычной таблицей маршрутизации Linux.

Версия 3.0.0 - крупная переработка внутренней реализации с сохранением исходной идеи проекта: простой и быстрый код, предсказуемое потребление памяти и минимум лишних механизмов.

## Основная идея

Типичный путь выглядит так:

```text
configured domain
       |
       v
   DNS answer
       |
       +-- CNAME -----------> learned domain
       |
       +-- HTTPS AliasMode ---> learned domain
       |
       +-- A -----------------> IPv4 address
                         |
                         v
                    /32 route
                         |
                         v
                 selected interface
```

Например, если `example.org` привязан к `wg0`, а DNS возвращает:

```text
example.org CNAME edge.example.net
edge.example.net A 1.1.1.1
```

AntiBlock запоминает связь `edge.example.net` с тем же правилом и создаёт маршрут к `1.1.1.1` через `wg0`.

Если позже приходит отдельный DNS-ответ уже непосредственно для `edge.example.net`, он также будет обработан по ранее выученному соответствию. Выученные через CNAME или HTTPS AliasMode домены сохраняются до следующей перезагрузки списков доменов.

## Маршрутизация

Для L3-интерфейсов, например WireGuard/TUN, AntiBlock создаёт обычный host route:

```text
1.1.1.1/32 dev wg0
```

Для Ethernet/L2-интерфейсов AntiBlock находит default gateway этого интерфейса в `/proc/net/route` и создаёт маршрут через него:

```text
1.1.1.1/32 via 192.168.1.1 dev eth0
```

Маршруты AntiBlock помечаются отдельным metric (`23117`). Это позволяет при старте удалить старые маршруты AntiBlock, не затрагивая произвольные чужие `/32` маршруты на тех же интерфейсах.

Для одного destination IPv4 в каждый момент существует только одно активное правило. Если более свежий DNS-ответ связывает тот же IP с другим интерфейсом, AntiBlock переносит маршрут на новое правило.

## TTL

Время жизни динамического маршрута определяется TTL соответствующей A-записи DNS.

Если тот же IP снова приходит для того же интерфейса, expiration не сокращается:

```text
expires = max(old_expires, new_expires)
```

Если тот же IP приходит уже для другого интерфейса, более свежий DNS-ответ побеждает, маршрут переносится, а TTL берётся из нового ответа.

Для внутренних таймеров используется `CLOCK_MONOTONIC`, поэтому коррекция системных часов через NTP не должна неожиданно состарить или продлить маршруты.

## CNAME и HTTPS AliasMode

AntiBlock распространяет принадлежность домена к правилу маршрутизации только по отношениям `domain -> domain`, которые действительно являются alias-связями:

- `CNAME`;
- `HTTPS` (`TYPE 65`) только в AliasMode, то есть при `SvcPriority=0`.

Например:

```text
blocked.example CNAME cdn.example
cdn.example     A     8.8.8.8
```

и HTTPS AliasMode:

```text
blocked.example HTTPS 0 edge.example
edge.example    A     9.9.9.9
```

В обоих случаях target наследует routing rule исходного домена, а последующая A-запись target создаёт обычный `/32` route. TTL маршрута по-прежнему берётся только из A-записи. TTL CNAME/HTTPS alias не используется для route lifetime, а learned mapping живёт до следующей перезагрузки domain lists.

`HTTPS` ServiceMode (`SvcPriority>0`) намеренно не используется как alias. `ipv4hint` также не превращается в route напрямую: AntiBlock сохраняет простой источник истины `A -> IPv4`, а TYPE 65 нужен только для настоящего AliasMode `domain -> domain`. AliasMode с `TargetName=.` ничего не обучает.

Обработка alias-связей не зависит от порядка Resource Records внутри DNS-ответа. Например, оба варианта обрабатываются одинаково:

```text
blocked.example CNAME cdn.example
cdn.example     A     8.8.8.8
```

и:

```text
cdn.example     A     8.8.8.8
blocked.example CNAME cdn.example
```

То же правило действует для смешанных цепочек CNAME + HTTPS AliasMode. Для этого alias-классификация распространяется отдельными ограниченными проходами по уже полученному DNS-пакету, после чего обрабатываются A-записи. Дополнительных больших структур данных для DNS-графа не создаётся.

## Память и структуры данных

В проекте используется исходная `array_hashmap`, которая изначально разрабатывалась для AntiBlock.

Хеш-таблица хранится одним массивом. Цепочки коллизий используют 32-битные индексы вместо указателей, поэтому нет отдельного `malloc` на каждый элемент и 64-битных pointer-связей между элементами.

Строки доменов находятся в одной последовательной arena. В payload доменной записи хранится компактное 32-битное значение:

```text
26 bit  offset в arena
 5 bit  номер routing rule
 1 bit  флаг match_subdomains
```

Та же hashmap используется для runtime-состояния динамических маршрутов.

При исчерпании места для learned CNAME/HTTPS alias AntiBlock выдаёт одно предупреждение
до следующей перезагрузки списков. При заполнении таблицы из 1024 маршрутов
предупреждение также выводится один раз и повторяется только после освобождения
места и следующего заполнения. Размеры таблиц автоматически не увеличиваются.

## Сборка

Нужны:

- компилятор C с поддержкой GNU99 (GCC или Clang);
- CMake >= 3.13;
- `libpcap` development files;
- `libcurl` development files.

Сборка использует GNU99, как и предыдущие версии проекта.

```sh
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Исполняемый файл:

```text
build/antiblock
```

## Использование

```text
AntiBlock 3.0.0
Usage:
  antiblock -r "iface path-or-url" ... -l IPv4:port [options]

Required:
  -r "iface source"   Domain source routed through iface (repeatable, max 32)
  -l IPv4:port        DNS response source to sniff, e.g. 192.168.1.1:53

Optional:
  -b path             Additional IPv4 CIDR blacklist
  -o directory        Directory for log.txt/stat.txt (default .)
  --log               Enable DNS operation log
  --stat              Enable stat.txt
  --test              Do not modify the kernel routing table
  -h, --help          Show this help
```

Пример:

```sh
sudo ./build/antiblock \
  -l 192.168.1.1:53 \
  -r "wg0 domains-vpn.txt" \
  -r "eth1 https://example.org/domains.txt" \
  --stat
```

Каждый `-r` связывает источник списка доменов с сетевым интерфейсом, через который должны маршрутизироваться найденные IP-адреса. Источником может быть локальный файл или HTTP(S) URL.

Обычная строка в списке соответствует самому домену и его поддоменам. Строка с префиксом `!` используется как exact-only правило. Ведущий `www.` нормализуется так же, как в предыдущей реализации.

## Перехват DNS

AntiBlock использует libpcap и слушает интерфейс `any`. Поддерживаются Linux cooked capture форматы SLL и SLL2.

Параметр `-l` задаёт IPv4-адрес и UDP-порт источника DNS-ответов, которые должен обрабатывать AntiBlock, например:

```text
-l 192.168.1.1:53
```

DNS-имена нормализуются в lowercase, поэтому matching не зависит от регистра.

## Blacklist

AntiBlock имеет встроенные исключения для приватных/служебных IPv4-сетей и позволяет добавить собственный список CIDR через `-b`.

Это позволяет не создавать динамические маршруты для адресов, которые не должны уходить через выбранные внешние интерфейсы.

## Корректное завершение

`SIGINT` и `SIGTERM` не выполняют сложный cleanup внутри signal handler. Обработчик только выставляет `volatile sig_atomic_t` флаг остановки, после чего основной цикл завершается и очистка маршрутов выполняется в обычном execution context.

## HTTP-загрузка списков доменов

Для HTTP/HTTPS-источников установлены таймауты: 5 секунд на соединение и
30 секунд на весь запрос (включая редиректы и получение тела ответа).
При ошибке загрузки текущая логика повторной попытки сохраняется.
Для экономии памяти отдельная резервная копия предыдущей таблицы доменов
не создаётся.

## Регрессионные тесты загрузки доменов

Без Docker можно проверить пустые файлы и HTTP-chunk, нормализацию `WWW.`, TTL=0,
границы learned-domain/route hashmap, счётчик ошибок добавления маршрутов
и коллизии/удаления в array_hashmap
с санитайзерами GCC и Clang (достаточно заголовков и библиотеки libcurl):

```sh
./tests/unit/run.sh
```

При использовании `--stat` файл `stat.txt` также показывает `Route add errors`:
число неудачных вызовов `SIOCADDRT` с начала текущего периода статистики.
Попытки добавить маршрут при заполненной userspace-таблице сюда не включаются.

## Интеграционные тесты

В репозитории есть Docker end-to-end тесты:

```sh
./tests/integration/run.sh
```

Тестовый образ строится на `archlinux:latest` и собирает AntiBlock двумя компиляторами: GCC и Clang. Один и тот же набор тестов затем запускается отдельно для каждого бинарника. Контейнеры используют `NET_ADMIN` и `NET_RAW`, без `--privileged` и без host networking, поэтому тестовые маршруты создаются внутри отдельного network namespace и не изменяют routing table хоста.

Тесты проверяют реальную цепочку:

```text
fake DNS server
      |
      v
 UDP DNS response
      |
      v
   libpcap
      |
      v
  AntiBlock
      |
      v
Linux routing table
```

На текущем наборе имеется 61 интеграционный тест. Один и тот же suite запускается на GCC release, Clang release и Clang с ASan+UBSan, поэтому полный acceptance-прогон выполняет 183 end-to-end проверки. Помимо исходных сценариев, suite проверяет:

- прямую A-запись;
- домен вне списка;
- встроенный и пользовательский blacklist;
- CNAME + A в одном ответе;
- learned CNAME и отдельный последующий DNS-ответ;
- сохранение learned CNAME после истечения DNS TTL самой CNAME-записи;
- learned CNAME для поддоменов target;
- multi-hop CNAME и независимость propagation от порядка RR;
- HTTPS AliasMode (`TYPE 65`, `SvcPriority=0`) и последующий A-ответ target;
- смешанную CNAME + HTTPS AliasMode цепочку независимо от порядка RR;
- то, что HTTPS ServiceMode (`SvcPriority>0`) не обучает target как alias;
- истечение TTL и пропуск записей с TTL=0 без создания или переноса маршрута;
- продление TTL повторным ответом;
- то, что более короткий TTL того же route rule не сокращает уже существующий expiration;
- перенос одного destination между двумя route rules и использование TTL нового наблюдения;
- L2 и L3 маршруты;
- выбор lowest-metric default gateway для L2;
- корректный отказ L2-интерфейса без default gateway;
- case-insensitive DNS names;
- matching поддоменов и exact-only правила `!domain`;
- нормализацию ведущего `www.` и CRLF domain lists;
- `--test`, `--log` и `--stat`;
- загрузку domain list по HTTP, ошибку HTTP source, таймаут зависшего сервера и повтор через 5 минут;
- пустой первый файл доменов и регистронезависимый `WWW.` в списках (включая `!`);
- разные ответы с одинаковым 16-битным DNS transaction ID;
- cleanup по `SIGTERM` и `SIGINT`;
- удаление при старте только маршрутов с metric AntiBlock;
- valid Additional/OPT section после Answer;
- malformed DNS packets: truncated header/question/RR, invalid RDLENGTH, invalid compression pointers, pointer loop, malformed CNAME, malformed HTTPS AliasMode TargetName, reserved label encoding и oversized decoded name;
- тот же набор под Clang ASan+UBSan для поиска memory-safety и undefined-behavior regressions.

Для каждого malformed DNS тест проверяет, что AntiBlock не падает, не создаёт ложный маршрут и после битого пакета продолжает корректно обрабатывать следующий валидный DNS-ответ.

## Нагрузочные и стресс-тесты

Отдельный Docker suite измеряет производительность полного DNS pipeline и проверяет стабильность под
длительной нагрузкой:

```sh
./tests/load/run.sh cloudflare-radar_top-1000000-domains_YYYYMMDD-YYYYMMDD.csv
```

AntiBlock загружает полный Cloudflare Radar Top 1M domain list. Для одноразовой подготовки локального DNS replay-cache `dns-client-test` по умолчанию выбирает 100 000 доменов через `-n 100000 --seed 701184`, явно выполняет A-прогон (`-A`) и запрашивает upstream resolver с консервативной скоростью 250 RPS. Результаты сохраняются как `cache-A.data` и `out_domains-A.txt`. Затем `dns-server-test` запускается с `-c cache-A.data`, и все измеряемые performance/stress прогоны полностью локальны и больше не обращаются к публичному DNS.

Нагрузку создают C-программы `dns-client-test` и `dns-server-test`; Python используется только как
orchestrator и не находится в измеряемом DNS hot path.

Suite содержит четыре сценария:

- GCC Release DNS throughput с полной таблицей доменов, включая cold lookup sweep и `--test`
  userspace route-state workload, actual local response rate и libpcap drop counters;
- GCC Release установку реальных `/32` routes с отдельным измерением времени изменения kernel
  routing table без post-send ожидания DNS-клиента;
- Clang ASan+UBSan DNS stress с полной таблицей доменов;
- Clang ASan+UBSan многократный real-route add/cleanup churn.

Performance-цифры не имеют жёсткого pass/fail threshold, так как зависят от CPU и окружения. При этом
crash, parser error, sanitizer diagnostic, переполнение route-state workload или оставшиеся после
cleanup AntiBlock routes считаются ошибкой теста.

Подробности и параметры нагрузки находятся в `tests/load/README.md`.

## Ограничения

Проект намеренно остаётся небольшим и специализированным. В версии 3.0.0 нет:

- IPv6/AAAA routing;
- DoH/DoT parsing;
- DNS-over-TCP parsing;
- маршрутизации по HTTPS ServiceMode/`ipv4hint`;
- обработки SVCB `TYPE 64` для web-routing;
- универсального policy-routing engine;
- потоков или тяжёлых framework-зависимостей.

AntiBlock ориентирован на простой сценарий DNS-driven IPv4 routing.

## OpenWrt

Для OpenWrt используются отдельные репозитории:

- `antiblock-openwrt-package` - пакет и init/UCI конфигурация;
- `luci-app-antiblock-openwrt-package` - LuCI web interface.

## Статья

Описание исходной идеи и реализации: [статья на Habr](https://habr.com/ru/articles/847412/).
