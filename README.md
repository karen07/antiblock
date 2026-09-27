# AntiBlock

AntiBlock is a DNS-based dynamic routing tool for Linux and OpenWrt. It watches DNS responses for selected domain lists, extracts the returned IPv4 addresses, and adds routes for those addresses through configured network interfaces.

Domain lists can be read from local files or downloaded from URLs. A single process can maintain several domain-list-to-gateway mappings, while an optional subnet list prevents selected networks from being added to the routing table.

The default build works in packet-sniffing mode with libpcap. The project is intended for selective routing based on DNS answers rather than for DNS filtering or a full proxy/VPN implementation.

## Сборка

Нужны `libpcap`, `libcurl`, CMake и git submodule `hashmap`.

```sh
git submodule update --init --recursive
cmake --preset release
cmake --build --preset release
```

Исполняемый файл:

```text
build/release/antiblock
```

## Использование

```text
Commands:
  It is necessary to enter from 1 to 32 values:
    Route domains from path/url through gateway:
      -r  "gateway1 https://test1.com"
      -r  "gateway2 /test1.txt"
      -r  "gateway2 /test2.txt"
      -r  "gateway1 https://test2.com"
      .....................................
  Required parameters:
    -l  "x.x.x.x:xx"  Address for sniffing packets with this src
  Optional parameters:
    -b  "/test.txt"   Subnets not added to the routing table
    -o  "/test/"      Log or statistics output folder
    --log              Show operations log
    --stat             Show statistics data
    --test             Test mode
```

Каждый `-r` связывает список доменов с интерфейсом/шлюзом, через который должны маршрутизироваться найденные IP-адреса. Источником списка может быть локальный файл или HTTP(S) URL.

## Как работает

В стандартной конфигурации `PCAP_MODE` AntiBlock слушает DNS-трафик через libpcap. Если ответ относится к домену из одного из настроенных списков, IPv4-адреса из ответа добавляются в соответствующую таблицу маршрутизации.

`-b` задает список IPv4 CIDR, которые нельзя добавлять в динамические маршруты. `--log` и `--stat` включают дополнительный вывод операций и статистики.

## OpenWrt

Для OpenWrt есть отдельные репозитории:

- `antiblock-openwrt-package` - пакет и init/UCI конфигурация;
- `luci-app-antiblock-openwrt-package` - LuCI web interface.

## Статья

Описание идеи и реализации: [статья на Habr](https://habr.com/ru/articles/847412/).
