# Решение проблем UmbraWG

Симптом → причина → что сделать → как проверить для типовых сбоев UmbraWG.
Документ собран по README/TODO/RELEASE/ARCHITECTURE/RESULTS четырёх
компонентов, `bench/README.md`, `bench/PEER-SCALING.md` и коду `uwg`,
`uwg-quick`, демона и модуля. Команды либо приведены в документации, либо
проверены по исходникам; внешние утилиты (`ip`, `ss`, `tcpdump`, `nstat`,
`ethtool`, `dkms`, `mokutil`, `perf`) — стандартные для Linux.

Содержание:

- 0. Быстрая диагностика
- 1. Интерфейс не поднимается / нет handshake
- 2. Низкая скорость / фрагментация
- 3. Сборка модуля
- 4. Упаковка и установка
- 5. `uwg` и `uwg-quick`
- 6. Параллельный RX демона
- 7. Отладка
- 8. Ссылки
- 9. Границы документа

Обозначения:

- `<iface>` — имя интерфейса, например `uwg0`;
- `<peer>` — публичный ключ пира в base64;
- команды `uwg` и `uwg-quick up|down|save` выполняются от root: UAPI-сокет
  принимает только uid 0; для netlink ядра достаточно `CAP_NET_ADMIN`, но
  UAPI всё равно потребует root. `uwg genkey|genpsk|pubkey` и `uwg-quick strip`
  работают без root;
- «ядро» — модуль `umbrawg`, «демон» — userspace `umbrawg` из `umbrawg-rs`.

## 0. Быстрая диагностика

| Симптом | Первое, что смотреть | Раздел |
|---|---|---|
| Интерфейса нет, `uwg show` не находит | `ip link show`, `uwg show interfaces`, `lsmod \| grep umbrawg`, `pgrep -a umbrawg` | 1.2 |
| Интерфейс есть, handshake 0 | `uwg show <iface> latest-handshakes`, `uwg show <iface> endpoints`, `tcpdump`, `ss -lunp` | 1.1, 1.3 |
| Сокет `/var/run/umbrawg/<iface>.sock` есть, но ничего не работает | `ss -xlp \| grep <iface>.sock`, `systemctl status umbrawg@<iface>` | 1.4 |
| Маленькие пакеты идут, большие зависают; скорость падает кратно | `ip link show <iface>`, `nstat -az \| grep -i frag`, `ping -M do` | 2.1 |
| `obf=1` в разы медленнее `obf=0`, ядра простаивают | MTU/GSO, `ethtool -k`, лог демона о TUN offload | 2.1, 2.2 |
| UDP-потери в iperf3, но ping/TCP целы | `nstat -az \| grep UdpRcvbufErrors`, `ip -s link show <iface>` | 2.4 |
| Демон пишет про урезанный буфер сокета | `journalctl -u umbrawg@<iface>`, `sysctl net.core.rmem_max` | 2.3 |
| Модуль не собирается или не загружается | `uname -r`, `make LLVM=1`, `dkms status`, `dmesg` | 3 |
| `uwg`/`uwg-quick` падают после установки пакета | `ldd $(command -v uwg)`, `stat /etc/umbrawg`, `systemctl cat` | 4 |
| Непонятен код возврата CLI | `uwg --help; echo $?`, `uwg version; echo $?` | 5.1 |
| `rust-par` медленнее `rust` | `UMBRAWG_RX_STATS=1`, `UMBRAWG_RX_SCHED` | 6 |
| Нужны подробности | `UMBRAWG_LOG_LEVEL=debug`, dynamic debug, `uwg show`, `nstat`, `perf` | 7 |

Полезно сразу определить бэкенд: у интерфейса ядра `ip -d link show` показывает
`kind umbrawg`, у TUN демона — `kind tun`. `uwg show interfaces` объединяет оба
списка.

```sh
ip -d link show dev uwg0
uwg show interfaces
```

## 1. Интерфейс не поднимается / нет handshake

### 1.1. Первый handshake теряется, если ядро стартует раньше демона

**Симптом.** Туннель поднимается не сразу, а примерно через 5 секунд; в
`latest-handshakes` сначала `0`, затем время появляется. В `tcpdump` видна
инициация и её повтор через 5 секунд.

**Причина.** Ядро инициирует handshake сразу после конфигурации, но
userspace-демон на другой стороне ещё не забиндил UDP-порт. Первая инициация
теряется, соединение поднимается на ретрае.

**Что сделать.** Настраивать стороны в порядке «сначала userspace, потом
ядро»:

1. Поднять и сконфигурировать userspace-демон на принимающей стороне:

   ```sh
   systemctl start umbrawg@uwg0
   uwg setconf uwg0 /etc/umbrawg/uwg0.conf
   ss -lunp | grep 51820
   ```

2. Убедиться, что демон слушает UDP-порт, и только затем настраивать сторону
   с модулем ядра:

   ```sh
   uwg setconf uwg0 /etc/umbrawg/uwg0.conf
   ```

3. Если обе стороны на одном хосте, не поднимать модуль и демон с одним именем
   интерфейса: TUN демона и netdev модуля не могут занимать одно имя.

**Как проверить.** Через несколько секунд после конфигурации ядра:

```sh
uwg show uwg0 latest-handshakes
uwg show uwg0 endpoints
ping -c 3 10.0.0.2
```

Ожидаемо: время handshake близко к `date +%s` (не `0`), endpoint не `(none)`,
ping проходит. Если первая инициация всё же потеряна, повтор через 5 секунд
должен поднять туннель.

**Источник.** `umbrawg-linux-kernel-module/README.md`, раздел «Troubleshooting →
Handshake is lost when the kernel starts first»; `TODO.md` модуля; раздел 5
`docs/ARCHITECTURE.md`.

### 1.2. Интерфейс не создаётся: модуль, ядро или бэкенд

**Симптом.** `ip link add dev uwg0 type umbrawg` завершается ошибкой
«unknown link type», `uwg show uwg0` — «interface not found», либо
`uwg-quick up` неожиданно поднимает userspace-демон вместо модуля.

**Причина.** Модуль не загружен, собран под другое ядро, не подписан для
Secure Boot; либо `uwg-quick` не смог создать интерфейс модуля и перешёл на
userspace-фолбэк.

**Что сделать.**

```sh
uname -r
modinfo umbrawg | grep -E '^(filename|version|vermagic)'
sudo modprobe umbrawg
lsmod | grep umbrawg
sudo ip link add dev uwg0 type umbrawg
sudo ip link set dev uwg0 up
```

Для userspace-демона интерфейс создаёт сам демон:

```sh
sudo umbrawg --foreground uwg0
```

`uwg-quick up` сначала пытается создать netdev модуля и при неудаче, если
`/sys/module/umbrawg` отсутствует и в `PATH` есть `umbrawg`, печатает
`[!] Missing WireGuard (UmbraWG) kernel module. Falling back to slow userspace
implementation.` и запускает демон. Если нужен именно модуль, загрузите его
заранее.

**Как проверить.**

```sh
ip -d link show dev uwg0
uwg show interfaces
```

Ожидаемо: `kind umbrawg` для модуля или `kind tun` для демона; интерфейс есть
в `uwg show interfaces`. Ошибка `modprobe: ... Invalid argument` или
`unknown symbol` означает несовпадение с ядром — см. раздел 3. Ошибка
`Key was rejected by service` — Secure Boot, см. 3.3.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Manual build,
Limitations); `crates/uwg-quick/src/commands.rs` (`add_if_with_module`,
`KERNEL_MODULE_PATH`); `crates/uwg-quick/src/lib.rs`.

### 1.3. Ключи, endpoint, AllowedIPs, порты и firewall

**Симптом.** Handshake не появляется вообще (`latest-handshakes` = `0`),
`transfer` не растёт, ping через туннель не идёт. При этом интерфейс поднят.

**Причина.** Одна из сторон использует не тот публичный ключ, неверный
`Endpoint`/порт, `AllowedIPs` не покрывает трафик, UDP-порт закрыт firewall,
либо endpoint-хостнейм разрешился в старый адрес.

**Что сделать.** Пройти чек-лист на обеих сторонах.

1. Ключи. Приватный ключ и публичный ключ должны быть парой, а `PublicKey`
   пира на одной стороне — совпадать с публичным ключом другой стороны:

   ```sh
   uwg pubkey < /etc/umbrawg/uwg0.key
   uwg show uwg0 public-key
   uwg showconf uwg0
   ```

   Ожидаемо: вывод `pubkey` совпадает с `public-key`; `PublicKey` в `[Peer]`
   на противоположной стороне равен этому значению. `PresharedKey`, если
   задан, должен совпадать на обеих сторонах.

2. Endpoint и порт. На инициаторе endpoint должен быть внешним адресом и
   UDP-портом принимающей стороны:

   ```sh
   uwg show uwg0 endpoints
   uwg show uwg0 listen-port
   ss -lunp | grep 51820
   ```

   Ожидаемо: endpoint не `(none)`, `listen-port` совпадает с портом из
   конфига, `ss` показывает слушающий UDP-сокет. За NAT endpoint — публичный
   адрес, на роутере/cloud security group открыт и проброшен UDP-порт.

3. `AllowedIPs`. Трафик, который должен идти в туннель, обязан попадать в
   `AllowedIPs` на обеих сторонах; источник пакета из туннеля проверяется по
   `AllowedIPs` пира.

   ```sh
   uwg show uwg0 allowed-ips
   ip route
   ip rule
   ```

   `uwg` предупреждает `Warning: AllowedIP has nonzero host part: ...`, если в
   CIDR есть биты хоста. Это не всегда ошибка, но лучше привести маску к сети.

4. Firewall. Проверить, что UDP-пакеты доходят до хоста, а не режутся:

   ```sh
   sudo tcpdump -ni any -vv 'udp port 51820'
   sudo nft list ruleset
   sudo iptables -S
   ```

   Ожидаемо: на принимающей стороне видны входящие пакеты от endpoint
   инициатора; в правилах нет `drop/reject` для этого UDP-порта. Если
   `tcpdump` на внешнем интерфейсе пакетов не видит — проблема в endpoint,
   NAT или firewall провайдера, а не в UmbraWG.

5. DNS. `Endpoint` с хостнеймом разрешается при `uwg setconf`; автоматического
   переразрешения в демоне и модуле нет (открытый вопрос в
   `docs/ARCHITECTURE.md`). После смены DNS-записи примените конфиг заново:

   ```sh
   uwg syncconf uwg0 <(uwg-quick strip uwg0)
   ```

6. Время. При сильном сдвиге часов назад handshake может отклоняться как
   старый. Проверить `timedatectl` и синхронизацию времени.

**Как проверить.** После исправления:

```sh
uwg show uwg0 latest-handshakes
uwg show uwg0 transfer
ping -c 3 <адрес-в-туннеле>
```

Ожидаемо: handshake обновляется, `transfer` растёт в обе стороны, ping без
потерь. Если handshake есть, а трафика нет — смотрите `AllowedIPs`, маршруты
(`ip route get <адрес>`) и firewall внутри туннеля.

**Источник.** `README.md` (Параметры обфускации, конфиги);
`umbrawg-linux-kernel-module/README.md` (Configuration — все параметры, кроме
`Jc/Jmin/Jmax`, должны совпадать); `docs/ARCHITECTURE.md` разделы 3 и 5;
`crates/umbrawg-config/src/endpoint.rs`; `crates/uwg/src/main.rs`
(`warn_about_host_bits`); `crates/uwg/src/output.rs`.

### 1.4. UAPI-сокет есть, но демон мёртв

**Симптом.** `/var/run/umbrawg/uwg0.sock` существует, но `uwg show uwg0`
сообщает, что интерфейс не найден, или уходит в netlink; `ss` не показывает
слушателя; процесс `umbrawg` отсутствует.

**Причина.** Демон был убит или упал, сокет остался. `uwg` при
`ConnectionRefused` удаляет такой сокет и считает, что UAPI-интерфейса нет;
демон при старте тоже удаляет stale-сокет, но если сокет живой и занят другим
процессом — возвращает `address is already in use` (`EADDRINUSE`).

**Что сделать.**

1. Проверить, жив ли демон и кто держит сокет:

   ```sh
   pgrep -a umbrawg
   systemctl status umbrawg@uwg0
   ss -xlp | grep uwg0.sock
   journalctl -u umbrawg@uwg0 -b --no-pager
   ```

2. Если процесса нет, перезапустить юнит:

   ```sh
   systemctl reset-failed umbrawg@uwg0
   systemctl start umbrawg@uwg0
   ```

3. Если сокет остался от убитого процесса и демон не стартует, удалить именно
   этот stale-сокет (только убедившись, что `pgrep umbrawg` пуст):

   ```sh
   rm -f /var/run/umbrawg/uwg0.sock
   systemctl start umbrawg@uwg0
   ```

4. Если сокет держит живой другой процесс, не удалять его: остановите старый
   экземпляр или используйте другое имя интерфейса.

**Как проверить.**

```sh
ss -xlp | grep uwg0.sock
uwg show uwg0
uwg show interfaces
```

Ожидаемо: сокет слушает процесс `umbrawg`, `uwg show` отдаёт конфигурацию,
интерфейс есть в `uwg show interfaces`. В журнале нет `address is already in
use` и `UAPI rejected connection`.

**Источник.** `crates/umbrawg-ctl/src/uapi.rs` (`has_interface`, `connect`);
`umbrawg-rs/crates/umbrawg-uapi/src/listener.rs` (`bind`,
`remove_stale_socket`, `AddressInUse`); `umbrawg-rs/crates/umbrawg-uapi/src/error.rs`.

## 2. Низкая скорость / фрагментация

### 2.1. MTU: underlay, TUN, S4 и 32 байта

**Симптом.** Ping маленькими пакетами идёт, большие пакеты теряются или
«зависают»; TCP-скорость падает, растут ретрансмиты; в стенде появляется
`FRAGMENTED`/`frag>0`. При неудачном MTU и обфускации скорость падает кратно:
GSO-фикс в отчётах дал 1.8–2.8×, а у эталонного Go с заглушкой обфускации
падение доходило до единиц Мбит/с.

**Причина.** Обфускация добавляет к внутреннему пакету `S4` байт и 32 байта
(16 заголовка + 16 тега Poly1305): транспортная датаграмма имеет вид
`S4 + 16 + внутренний пакет + 16`. Если итоговая датаграмма больше MTU
подложки (или лимита GSO), включается IP-фрагментация либо GSO отключается
для каждого пакета. В отчёте `docs/RESULTS.md` (§12) датаграмма `obf=1` при
TUN MTU 1420 и `S4=28` равна `28 + 16 + 1420 + 16 = 1480`, что больше старого
лимита GSO 1472; после фикса GSO скорость `obf=1` выросла в 1.8–2.8 раза.

**Что сделать.**

1. Посчитать безопасный TUN MTU по формуле стенда:

   ```text
   TUN_MTU <= UNDERLAY_MTU - (OVERHEAD_BASE + S4),  OVERHEAD_BASE = 80
   ```

   Для underlay 1500 и `S4=28` предел — **1392**; в `bench/README.md`
   рекомендуется консервативное значение **1380**. Альтернатива из
   `docs/RESULTS.md`: underlay не меньше **1508**, тогда TUN 1420 помещается.
   Для underlay 9000 TUN 1420 безопасен.

2. Задать MTU явно. `uwg-quick` при отсутствии `MTU` считает
   `MTU = MTU маршрута до endpoint − 80`; при underlay 1500 это 1420, то есть
   **не учитывает `S4`**. Для профиля с `S4=28` добавьте в `[Interface]`:

   ```ini
   MTU = 1380
   ```

   Затем:

   ```sh
   uwg-quick down uwg0
   uwg-quick up uwg0
   ```

   Для модуля без `uwg-quick` MTU задаётся на интерфейсе:

   ```sh
   ip link set dev uwg0 mtu 1380
   ```

3. Если underlay позволяет, используйте jumbo (9000): тогда TUN 1420 не
   фрагментируется и GSO работает.

**Как проверить.**

```sh
ip link show dev uwg0
ip route get <endpoint-ip>
ping -M do -s 1352 <адрес-в-туннеле>     # TUN 1380: 1380 - 28
ping -M do -s 1472 <endpoint-ip>         # underlay 1500: 1500 - 28
nstat -az | grep -i frag
ip -s link show dev uwg0
```

Ожидаемо: `mtu 1380` (или меньше), `ping -M do` проходит без
`Frag needed and DF set`; `nstat` не показывает прироста `IpFrag*` во время
прогона; в `ip -s link` нет роста `errors/dropped`. В стенде `bench.sh` при
фрагментации пишет `FRAGMENTED` в `.diag` и `frag>0` в CSV — это признак
неправильного MTU, а не нормы (обход только `ALLOW_FRAGMENT=1` для
диагностики).

**Источник.** `bench/README.md` (MTU-guard, `OVERHEAD_BASE`, `TUN_MTU`);
`docs/RESULTS.md` §12 (формула `S4 + 16 + payload + 16`, 1392/1508,
GSO-фикс); `crates/uwg-quick/src/mtu.rs` (`TUNNEL_OVERHEAD = 80`,
`auto_mtu`); `bench/bench-lib.sh` (`mtu_overhead`, `mtu_verdict`);
`umbrawg-linux-kernel-module/README.md` (Configuration, GSO).

### 2.2. GSO/GRO: veth и реальный NIC ведут себя по-разному

**Симптом.** На стенде с veth скорость одна, на реальной машине — другая;
`obf=1` кратно медленнее `obf=0` при незагруженных ядрах (в старых сборках —
в 2–3 раза); в логе демона `tun offload is unavailable (...)`; `tcpdump`
показывает большие UDP-пакеты, похожие на фрагменты.

**Причина.** Модуль штатно агрегирует отправку в UDP GSO (jumbo до 23 КБ), а
стек сегментирует перед проводом — это не IP-фрагментация. UDP GRO на сокете
модуля не реализован (`gro_receive = NULL`, `ACCEPT_L4` не выставлен), оценка
выгоды 2–4% остаётся гипотезой. Демон использует `UDP_SEGMENT`/`UDP_GRO` и
virtio-net offload для TUN; если TUN offload недоступен, он переходит в
packet mode с предупреждением. На veth нет RSS, очереди включаются только
`ethtool -L`, а один поток живёт на одной очереди; на реальном NIC RSS
раскладывает потоки по ядрам, поэтому картина другая.

**Что сделать.**

1. Проверить offload на подложке и NIC:

   ```sh
   ethtool -k <underlay-iface> | grep -E 'tx-udp-segmentation|rx-udp-gro|generic-(receive|segmentation)'
   ethtool -l <underlay-iface>
   ethtool -x <underlay-iface>      # на veth: Operation not supported
   ```

   Для veth при необходимости включить очереди на обоих концах:

   ```sh
   ethtool -L <veth> rx <N> tx <N>
   ```

2. Убедиться, что демон не потерял offload:

   ```sh
   journalctl -u umbrawg@uwg0 -b | grep -i 'tun offload'
   ```

   Строка `tun offload is unavailable (...); falling back to packet mode`
   означает работу без GSO/GRO — это объясняет падение, а не дефект
   обфускации.

3. Не включать и не отключать GSO вручную «для проверки»: в текущей сборке
   демона лимиты заданы явно (`GsoLimits::new(65507, 64)`), а на модуле GSO —
   часть send path. Если MTU увеличен, сначала вернитесь к разделу 2.1.

**Как проверить.**

```sh
sudo tcpdump -ni any -vv 'udp port 51820'
sudo nstat -az | grep -Ei 'frag|udp'
cat /proc/net/softnet_stat
ip -s link show dev uwg0
```

Ожидаемо: `tcpdump` на отправителе может показывать GSO-суперпакеты больше MTU
— это нормально, если `nstat` не показывает роста `IpFragCreates`, а на
принимающей стороне пакеты собираются без ошибок. Рост `time_squeeze` в
`/proc/net/softnet_stat` и `UdpRcvbufErrors` указывает на softirq/буфер
приёма, а не на фрагментацию. `FRAGMENTED` в `.diag` стенда — реальная
фрагментация.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Limitations, GSO);
`docs/PERFORMANCE.md` (GSO и фрагментация, UDP GRO, UDP-потери);
`bench/README.md` (veth без RSS, `ethtool -L`, RPS);
`umbrawg-rs/README.md` (буферы, TUN offload); `umbrawg-rs/crates/umbrawg/src/lib.rs`
(`TunSet::open`, fallback); `docs/RESULTS.md` §12.

### 2.3. `net.core.rmem_max`/`wmem_max` режут `SO_RCVBUF`

**Симптом.** В журнале демона один раз при создании сокета:

```text
SO_RCVBUF was clamped by the kernel: effective 212992 bytes,
requested 4194304 bytes; raise net.core.rmem_max or lower UMBRAWG_SOCKET_BUFFER
```

Под нагрузкой `obf=1` растут потери, хотя CPU и туннель не перегружены.

**Причина.** Демон запрашивает `SO_RCVBUF`/`SO_SNDBUF` размером
`UMBRAWG_SOCKET_BUFFER` (по умолчанию 4 МиБ), но ядро молча урезает запрос до
`net.core.rmem_max`/`wmem_max` (часто 212992). Маленький приёмный буфер теряет
всплески до обработки.

**Что сделать.**

```sh
sysctl net.core.rmem_max net.core.wmem_max
```

Поднять лимиты (как в README демона):

```sh
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
```

Для сохранения после перезагрузки добавьте эти значения в
`/etc/sysctl.d/99-umbrawg.conf` (или в systemd-sysctl). Либо уменьшите
`UMBRAWG_SOCKET_BUFFER` до значения, которое ядро не урезает; допустимый
диапазон — от 217088 (212 КиБ) до 67108864 (64 МиБ), некорректное значение —
ошибка старта, а не молчаливый откат.

**Как проверить.**

```sh
sysctl net.core.rmem_max net.core.wmem_max
journalctl -u umbrawg@uwg0 -b | grep -i clamped
ss -uanm | grep 51820
```

Ожидаемо: предупреждения `clamped` больше нет; `ss` показывает `skmem` с
буферами порядка запрошенных (Linux возвращает удвоенное значение
`getsockopt`, демон это учитывает); потери на ровном месте исчезли.

**Источник.** `umbrawg-rs/README.md` («Буферы UDP-сокета», переменные
`UMBRAWG_SOCKET_BUFFER`); `umbrawg-rs/crates/umbrawg/src/lib.rs`
(`socket_buffer_bytes`); `docs/PERFORMANCE.md` (UDP-потери).

### 2.4. UDP-потери в iperf3 — это не дропы туннеля

**Симптом.** `iperf3 -u` показывает потери, но ping и TCP идут без потерь;
в `obf=1` потери больше, чем в `obf=0`.

**Причина.** В замерах потери видны из-за переполнения приёмного буфера
`iperf3` (`RcvbufErrors`), а не из-за дропов туннеля. Это ограничение клиента
и стенда, а не протокола.

**Что сделать.** Разделить счётчики:

```sh
nstat -az | grep -E 'UdpRcvbufErrors|UdpInErrors'
ip -s link show dev uwg0
ss -uanm | grep -E 'iperf3|51820'
```

- растёт `UdpRcvbufErrors` на принимающей стороне — увеличьте приёмный буфер
  `iperf3` (`-w`) и/или снизьте предложенную скорость, это артефакт замера;
- растут `errors/dropped` на `uwg0` — это уже туннель, смотрите раздел 2.1 и
  счётчики приёма демона (раздел 6);
- растёт `time_squeeze` в `/proc/net/softnet_stat` — упирается softirq/CPU,
  а не буфер.

**Как проверить.** Повторить замер с большим `-w` и меньшей скоростью:
потери должны упасть без изменения конфигурации туннеля; счётчики `uwg0` при
этом не растут. В стенде смотрите `.diag`/CSV: `FRAGMENTED` и `frag>0` — это
фрагментация, `lost_percent` — потери UDP.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Limitations — UDP loss
from `RcvbufErrors`); `docs/PERFORMANCE.md` («UDP-потери в замерах»);
`bench/README.md` (UDP-режимы, диагностика); `docs/RESULTS.md` (UDP-матрица).

## 3. Сборка модуля

### 3.1. Linux 7.x и компилятор ядра

**Симптом.** `make` падает на флагах вроде `-fms-anonymous-structs`; либо
модуль собирается, но не загружается на другом ядре.

**Причина.** UmbraWG требует Linux **7.0 или новее** (совместимость со
старыми ядрами удалена). Для ядра, собранного clang (CachyOS, часть Fedora),
обязателен `make LLVM=1`; для GCC-ядра (stock Arch) — обычный `make`. Ядро
отклоняет флаги «чужого» компилятора.

**Что сделать.** Определить компилятор по заголовкам и собрать тем же:

```sh
uname -r
ls -l /lib/modules/$(uname -r)/build
grep -E '^CONFIG_CC_IS_CLANG=' /lib/modules/$(uname -r)/build/.config
```

Если `.config` в заголовках нет, используйте fallback из CI:

```sh
grep -E '^CONFIG_CC_IS_CLANG=' /lib/modules/$(uname -r)/build/include/config/auto.conf
```

- `CONFIG_CC_IS_CLANG=y` → `make LLVM=1`;
- `CONFIG_CC_IS_CLANG=n` → `make` (без `LLVM=1`).

Сборка и установка:

```sh
cd umbrawg-linux-kernel-module/src
make LLVM=1
sudo make install
sudo modprobe umbrawg
```

Для clang-ядра `LLVM=1` нужен и для `module-debug`:

```sh
make module-debug LLVM=1
```

**Как проверить.**

```sh
modinfo ./umbrawg.ko | grep -E '^(filename|version|vermagic)'
modinfo umbrawg | grep '^vermagic'      # после установки
lsmod | grep umbrawg
```

Ожидаемо: `vermagic` совпадает с `uname -r` (с учётом локальной версии),
`modprobe` не ругается, `lsmod` показывает модуль. Версия у ручной сборки —
`UMBRAWG_VERSION` (по умолчанию `0.3.0`), у пакета — `0.3.0`.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Important, Manual
build, CI — определение компилятора по `CONFIG_CC_IS_CLANG`); `TODO.md`
модуля.

### 3.2. `srcversion` не показывает правки заголовков

**Симптом.** После изменения `.h` и пересборки `modinfo -F srcversion`
показывает старое значение; кажется, что модуль не пересобрался.

**Причина.** `srcversion` не меняется, если менялись только заголовки. Это
документированное ограничение, а не признак неудачной сборки.

**Что сделать.** Проверять пересборку по времени `.ko`, размеру, хешу или
логу:

```sh
stat -c '%y %s %n' src/umbrawg.ko
md5sum src/umbrawg.ko
modinfo -F srcversion src/umbrawg.ko
```

**Как проверить.** После правки заголовка время и хеш `.ko` изменились, в
логе сборки компилировались нужные файлы; `srcversion` при этом может
остаться прежним — это ожидаемо. Для чистой проверки: `make clean && make
LLVM=1`.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Note после Manual
build); `TODO.md` модуля.

### 3.3. DKMS: заголовки, подпись/MOK, add/build/install

**Симптом.** Пакет `umbrawg-dkms` установлен, но модуль не собран или не
загружается; `dkms status` пуст/`built` без `installed`; `modprobe` даёт
`Key was rejected by service`.

**Причина.** Нет заголовков ядра, не хватает toolchain, версия в `dkms.conf`
не совпадает с каталогом, либо Secure Boot не принимает неподписанный модуль.

**Что сделать.**

1. Установить `dkms` и заголовки **текущего** ядра (имена зависят от
   дистрибутива):

   ```sh
   # Debian/Ubuntu
   sudo apt install dkms linux-headers-$(uname -r)
   # Fedora/RHEL
   sudo dnf install dkms kernel-devel
   # Arch: пакет заголовков соответствующего ядра, например linux-headers
   ```

2. Ручной DKMS-цикл (для исходников из `src/`, версия по умолчанию `0.3.0`):

   ```sh
   cd umbrawg-linux-kernel-module/src
   sudo make dkms-install
   sudo dkms add -m umbrawg -v 1.0.0
   sudo dkms build -m umbrawg -v 1.0.0
   sudo dkms install -m umbrawg -v 0.3.0
   ```

   Для пакета версия — `0.3.0`. Если сборка пакета не удалась, `.install`-скрипт не
   прерывает установку, а советует `dkms autoinstall`:

   ```sh
   dkms status
   sudo dkms autoinstall
   ```

3. Secure Boot. Проверить режим и подпись:

   ```sh
   mokutil --sb-state
   modinfo -F signer umbrawg
   sudo dmesg | grep -Ei 'Key was rejected|module verification failed|unsigned module'
   ```

   Если Secure Boot включён, а `signer` пуст, модуль не загрузится. Нужно
   подписать его ключом, зарегистрированным в MOK (Machine Owner Key), либо
   отключить Secure Boot. DKMS-подпись возможна только от root с настроенным
   MOK-ключом; регистрация публичной части выполняется через
   `sudo mokutil --import <файл.der>` и подтверждение `Enroll MOK` при
   перезагрузке. Конкретный путь к ключу зависит от дистрибутива.

**Как проверить.**

```sh
dkms status
modinfo -n umbrawg
modinfo umbrawg | grep -E '^(version|signer|vermagic)'
sudo modprobe umbrawg && lsmod | grep umbrawg
```

Ожидаемо: `dkms status` содержит `umbrawg/<version>, <kernel>: installed`;
`modinfo` показывает версию и (при Secure Boot) непустой `signer`;
`modprobe` проходит. Если сборка падает, лог — в
`/var/lib/dkms/umbrawg/<version>/build/make.log`.

**Источник.** `umbrawg-linux-kernel-module/README.md` (Manual build, DKMS,
Packages — заголовки нужны на целевой машине); `contrib/arch/README.md`
модуля (полный цикл DKMS, `make LLVM=1`, «подпись возможна только от root с
настроенным MOK-ключом»); `src/dkms.conf`, `contrib/arch/umbrawg-dkms/*.install`.

## 4. Упаковка и установка

### 4.1. Тарбол, deb/rpm/Arch и зависимости

**Симптом.** После установки `uwg` не запускается:
`error while loading shared libraries: libgcc_s.so.1`; или сборка из тарбола
падает на отсутствующем `../netlink-packet-umbrawg`; или пакет не ставится
из-за зависимостей.

**Причина.** Тарбол исходников содержит два дерева рядом (path-зависимость
Cargo), а бинарные сборки требуют glibc и `libgcc_s` целевой системы. Пакеты
Arch явно зависят от `glibc`, `gcc-libs`, `iproute2`; deb/rpm тянут
`iproute2` и `shlibs`/`iproute`.

**Что сделать.**

1. Исходники: собрать тарбол из корня tools (нужен соседний
   `netlink-packet-umbrawg`):

   ```sh
   scripts/package/make-dist.sh
   ```

   Ожидаемо: `dist/umbrawg-tools-<version>.tar.gz`, внутри каталоги
   `umbrawg-tools/` и `netlink-packet-umbrawg/`. Если скрипт пишет
   `error: .../netlink-packet-umbrawg not found`, разложите деревья рядом.

2. Бинарники: проверить зависимости.

   ```sh
   ldd "$(command -v uwg)"
   ldd "$(command -v uwg-quick)"
   uwg --version
   ```

   Ожидаемо: нет `not found`; на Arch при ошибке `libgcc_s.so.1` установите
   `gcc-libs` (на Debian — `libgcc-s1`). Бинарники из CI собраны на
   Ubuntu 22.04 (glibc 2.35), для более старой glibc нужна пересборка;
   ARM-бинарники требуют соответствующего arm64/armhf userland.

3. Пакеты:

   ```sh
   sudo apt install ./dist/umbrawg-tools_*.deb     # Debian/Ubuntu
   sudo dnf install ./dist/umbrawg-tools-*.rpm     # Fedora/RHEL
   sudo pacman -U ./umbrawg-tools-*.pkg.tar.zst    # Arch (если пакет уже собран)
   ```

   Ожидаемо: `uwg --version` и `uwg-quick --help` работают; каталог
   `/etc/umbrawg` создан с правами `0700`.

**Источник.** `README.md` (Упаковка, Сборка в Docker);
`scripts/package/make-dist.sh`; `contrib/arch/README.md` (зависимости
`glibc`, `gcc-libs`, `iproute2`); `debian/control`; `umbrawg-tools.spec`;
`umbrawg-rs/README.md` (Cross build, GLIBC).

### 4.2. AUR: стабильный пакет и `-git`

**Симптом.** `makepkg` для стабильного `umbrawg-tools` падает на проверке
контрольных сумм; `-git` собирается, но тянет другие ветки.

**Причина.** В стабильных PKGBUILD стоит заглушка
`TODO_UPDPKGSUMS_AFTER_FIRST_TAG` до первого тега; `-git`-пакет сам клонирует
`master` tools и `main` netlink с GitHub.

**Что сделать.** Команды `makepkg`/`updpkgsums` выполняются от обычного
пользователя, не от root; `updpkgsums` входит в `pacman-contrib`:

```sh
cd contrib/arch/umbrawg-tools
updpkgsums
makepkg --printsrcinfo > .SRCINFO
makepkg -si
```

До появления тегов используйте `umbrawg-tools-git`; для него `updpkgsums` не
нужен (суммы `SKIP`). Стабильный пакет собирается только после тегов: его
`source` — архивы `v0.2.0` tools и `v0.3.0` netlink. Аналогично для
`umbrawg-dkms` и `umbrawg-daemon`: стабильные пакеты ждут тегов и
`updpkgsums`, `-git` работает без них.

**Как проверить.** `makepkg -si` завершился, `pacman -Ql umbrawg-tools-git`
показывает `/usr/bin/uwg`, `uwg --version` запускается из установленного
пакета. Для стабильного — `makepkg --printsrcinfo` совпадает с `.SRCINFO`.

**Источник.** `RELEASE.md` (Arch/AUR); `contrib/arch/README.md` (подготовка,
`updpkgsums`, `.SRCINFO`); `umbrawg-linux-kernel-module/contrib/arch/README.md`;
`umbrawg-rs/TODO.md` (пакетирование).

### 4.3. Права `/etc/umbrawg`, UAPI только root, CAP_NET_ADMIN

**Симптом.** `uwg` не может подключиться к демону; в журнале
`UAPI rejected connection from uid ...`; демон не создаёт TUN; конфиг читается
другим пользователем.

**Причина.** `/etc/umbrawg` должен быть `0700`, каталог сокетов — `0700`,
сокет — `0600`, UAPI принимает только uid 0. Демону нужен `CAP_NET_ADMIN` для
TUN и настройки сети.

**Что сделать.** Проверить и исправить права:

```sh
stat -c '%a %U:%G %n' /etc/umbrawg /var/run/umbrawg
ls -l /var/run/umbrawg/uwg0.sock
```

Ожидаемо: `700 root:root` у каталогов, `srw------- root root` у сокета.
Пакеты создают `/etc/umbrawg` с `0700`; если каталог создан вручную,
`chmod 700 /etc/umbrawg` и `chown root:root /etc/umbrawg`.

Проверить юнит:

```sh
systemctl cat umbrawg@uwg0 | grep -E 'CapabilityBoundingSet|AmbientCapabilities|User|Group'
systemctl show -p AmbientCapabilities -p CapabilityBoundingSet umbrawg@uwg0
```

Ожидаемо: в выводе есть `CAP_NET_ADMIN` (в юните демона —
`AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN`);
юнит не запускается от непривилегированного пользователя. `uwg` и
`uwg-quick up|down|save` запускайте от root; `uwg show` также требует root,
потому что UAPI отклоняет другие uid.

**Как проверить.** `uwg show uwg0` от root работает; от другого пользователя
завершается ошибкой, а если бэкенд — демон, в его журнале появляется
`UAPI rejected connection from uid <N>`. Это ожидаемая защита, а не сбой.

**Источник.** `debian/rules` (`install -d -m 0700 .../etc/umbrawg`);
`umbrawg-tools.spec` (`%attr(0700,root,root)`); `contrib/arch/umbrawg-tools/PKGBUILD`
(`install -dpm0700`); `umbrawg-rs/crates/umbrawg-uapi/src/listener.rs`
(каталог `0700`, сокет `0600`, `SO_PEERCRED`, authorizer `uid == 0`);
`umbrawg-rs/systemd/umbrawg@.service`.

### 4.4. `PrivateDevices` и `/dev/net/tun`

**Симптом.** Демон под systemd падает с ошибкой открытия TUN
(`No such file or directory`), хотя вручную запускается.

**Причина.** `PrivateDevices=yes` создаёт приватный `/dev`, в котором нет
`/dev/net/tun`. Юнит демона намеренно не использует `PrivateDevices`; доступ
к устройству ограничен `DevicePolicy=closed` + `DeviceAllow=/dev/net/tun rw`.

**Что сделать.** Проверить фактический юнит и наличие устройства:

```sh
systemctl cat umbrawg@uwg0 | grep -E 'PrivateDevices|DevicePolicy|DeviceAllow'
ls -l /dev/net/tun
```

Ожидаемо: нет `PrivateDevices=yes`; есть `DeviceAllow=/dev/net/tun rw`;
`/dev/net/tun` — символьное устройство. Если устройства нет, загрузите модуль
`tun` (`sudo modprobe tun`) и проверьте, что контейнер/namespace его пробрасывает.

**Как проверить.** После `systemctl restart umbrawg@uwg0`:

```sh
systemctl status umbrawg@uwg0
journalctl -u umbrawg@uwg0 -b --no-pager | grep -i tun
ip -d link show dev uwg0
```

Ожидаемо: демон активен, `kind tun`, ошибок открытия TUN нет.

**Источник.** `umbrawg-rs/README.md` (systemd — почему не используется
`PrivateDevices`); `umbrawg-rs/systemd/umbrawg@.service` (`DevicePolicy`,
`DeviceAllow`, `ReadWritePaths`); `umbrawg-rs/crates/umbrawg/src/lib.rs`
(`TunSet::open`).

### 4.5. Какой `umbrawg@.service` установлен

**Симптом.** После установки пакетов параметры юнита не совпадают с
ожидаемыми (разный набор capability/опций), `systemctl cat` показывает не то,
что в README.

**Причина.** В дереве есть две версии юнита: `systemd/umbrawg@.service` в
tools (его ставят deb/rpm) и `systemd/umbrawg@.service` в демоне (его ставит
Arch-пакет `umbrawg-daemon`; в Arch пакет tools юнит намеренно не включает,
чтобы пакеты не конфликтовали файлом).

**Что сделать.** Смотреть фактический файл и владельца пакета:

```sh
systemctl cat umbrawg@uwg0
dpkg -S /lib/systemd/system/umbrawg@.service 2>/dev/null
rpm -qf /usr/lib/systemd/system/umbrawg@.service 2>/dev/null
pacman -Qo /usr/lib/systemd/system/umbrawg@.service 2>/dev/null
```

Ожидаемо: один владелец; при установке из AUR юнит принадлежит
`umbrawg-daemon`/`umbrawg-daemon-git`, а не `umbrawg-tools`. Если файл
перезаписан вручную, верните пакетный (`pacman -S umbrawg-daemon` или
`apt install --reinstall umbrawg-tools`).

**Источник.** `contrib/arch/README.md` (состав пакета tools — без
`umbrawg@.service`); `debian/rules`, `umbrawg-tools.spec` (юнит входит в
tools); `umbrawg-rs/contrib/arch/umbrawg-daemon/PKGBUILD`; оба
`systemd/umbrawg@.service`.

## 5. `uwg` и `uwg-quick`

### 5.1. Коды возврата, `-v` и справка

**Симптом.** Скрипт считает `uwg` успешным/неуспешным не так, как ожидалось;
`-v` воспринимается как ошибка.

**Причина.** `uwg` следует legacy `wg`: успех/справка/версия — `0`, ошибки
использования и выполнения — `1`, диагностика в stderr. `uwg-quick` — порт
shell-версии: ошибки `Die`/I/O — `1`, но упавшая внешняя команда возвращает
свой статус (как `set -e` в shell).

**Что сделать / проверить.**

```sh
uwg --version; echo $?        # 0
uwg -v; echo $?               # 0, короткий флаг версии
uwg help >/dev/null; echo $?  # 0
uwg --help >/dev/null; echo $? # 0
uwg bogus >/dev/null; echo $?  # 1, сообщение в stderr
uwg show does-not-exist; echo $? # 1
uwg-quick --help >/dev/null; echo $? # 0
uwg-quick >/dev/null; echo $?  # 1, usage в stderr
uwg-quick strip uwg0 >/dev/null; echo $? # 0 без root при наличии конфига
```

Ожидаемо: коды как в комментариях (для `strip` нужен существующий
`/etc/umbrawg/uwg0.conf`). `uwg -V` не поддерживается (в отличие от
`-v`). `uwg-quick up|down|save` без root пытается перезапуститься через
`sudo`; если `sudo` не установлен, код `127`; если пользователь не прошёл
аутентификацию — статус `sudo`. При падении `ip`, `resolvconf` или `nft`
`uwg-quick` вернёт статус этой команды (1–255), а не всегда 1 — это важно в
скриптах.

**Источник.** `README.md` (Использование — коды возврата);
`crates/uwg/src/main.rs` (`report_parse_error`, `ExitCode`);
`crates/uwg/src/cli.rs` (`-v`, `-h`, `version`, `help`);
`crates/uwg-quick/src/main.rs` (`requires_root`, `auto_su`, exit codes);
`crates/uwg-quick/src/error.rs` (`exit_code`, `normalize_status`).

### 5.2. `AdvancedSecurity` — только ядро

**Симптом.** `AdvancedSecurity = on` задан на демоне, но `uwg show <iface>
advanced-security` показывает `yes`, а реальной защиты нет; или на одной
стороне `unsupported`.

**Причина.** `AdvancedSecurity` (`UWGPEER_A_ADVANCED_SECURITY`) реально
реализован только в модуле ядра. Userspace-демон принимает
`advanced_security=1|0` в UAPI, хранит и отражает значение, но не применяет
его. Если флаг не задавался, строка в `get=1` не выводится, а `show` пишет
`unsupported`.

**Что сделать.**

```sh
uwg show uwg0 advanced-security
uwg showconf uwg0 | grep AdvancedSecurity
```

Ожидаемо: `yes`/`no` для заданного флага, `unsupported` — если не задан.
Для реальной защиты настройте модуль ядра на обеих сторонах; на демоне это
информационное поле и не меняет обработку пакетов.

**Источник.** `README.md` (Параметры обфускации, Использование);
`TODO.md` («Известные проблемы — AdvancedSecurity через userspace UAPI»);
`docs/ARCHITECTURE.md` (инвариант 4, раздел 5); `umbrawg-rs/README.md`
(UAPI `advanced_security`); `crates/uwg/src/output.rs`
(`advanced_security_text`).

### 5.3. `strip` без root, `up/down` с root, DNS и firewall

**Симптом.** `uwg-quick up` падает на DNS/firewall; `strip` просит пароль;
`up` пишет «already exists»; после `down` остались правила/маршруты.

**Причина.** `strip` — чтение конфига, root не нужен. `up/down/save` меняют
TUN, маршруты, DNS и firewall и требуют root. DNS настраивается через
`resolvconf`, firewall — через `nft` (предпочтительно) или
`iptables-restore`; для default route вызывается
`sysctl net.ipv4.conf.all.src_valid_mark=1`. `Table = off` отключает
маршруты и firewall-правила (они создаются только вместе с default route),
но DNS всё равно применяется.

**Что сделать.**

```sh
# без root: только печать конфига для uwg setconf
uwg-quick strip uwg0 > /tmp/uwg0.stripped

# с root: поднять/опустить
sudo uwg-quick up uwg0
sudo uwg-quick down uwg0
```

Проверить наличие внешних команд:

```sh
command -v resolvconf
command -v nft
command -v iptables-restore
command -v sysctl
```

Если `resolvconf` нет, установите `openresolv`/`systemd-resolvconf` или
уберите `DNS` из конфига. Если нет `nft`, используется `iptables-restore`;
нужен хотя бы один бэкенд и `procps-ng` для `sysctl` (optdepends пакета).
`strip` не должен запрашивать root и не должен содержать `Address`, `DNS`,
`MTU`, `Table`, `PreUp/PostUp/PreDown/PostDown`, `SaveConfig`:

```sh
grep -E '^(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)' /tmp/uwg0.stripped
```

Ожидаемо: пусто; вывод состоит из `[Interface]`/`[Peer]` и ключей, понятных
`uwg setconf`.

**Как проверить `up/down`.**

```sh
ip -d link show dev uwg0
ip route show table all | grep uwg0
nft list ruleset | grep -A5 uwg0
resolvectl status 2>/dev/null || cat /etc/resolv.conf
```

Ожидаемо: интерфейс `kind umbrawg`/`tun`, маршруты для `AllowedIPs`, правила
nft/iptables с комментарием/именем интерфейса, DNS из конфига. `uwg-quick up`
на существующем интерфейсе печатает `` `uwg0' already exists `` — сначала
`down`; `uwg-quick down` на отсутствующем — `` `uwg0' is not a WireGuard
interface ``.

**Источник.** `crates/uwg-quick/src/main.rs` (`requires_root`);
`crates/uwg-quick/src/commands.rs` (`add_route`, `add_default`, `up`, `down`);
`crates/uwg-quick/src/firewall.rs` (`nft`/`iptables-restore`);
`crates/uwg-quick/src/dns.rs` (`resolvconf`); `crates/uwg-quick/src/usage.rs`;
`README.md` (Использование, переменные `UWG_QUICK_USERSPACE_IMPLEMENTATION`).

## 6. Параллельный RX демона

### 6.1. Режим экспериментальный и на одном пире медленнее

**Симптом.** С `UMBRAWG_PARALLEL_RX=1` один пир показывает меньше, чем без
режима; в multi-peer тоже нет обещанного прироста.

**Причина.** Режим opt-in. В final4 он медленнее обычного `rust` на
7.2–17.9% на одном пире в 7 из 8 ячеек матрицы (исключение — 3c c=1 obf=1,
+4.8%) и на 8.8%/15.6% в multi-peer. `sched=peer` привязывает пира к одному
воркеру по `hash(public_key) % N`, поэтому один пир не параллелится; выигрыш
мог бы дать только несколько пиров, но в final4 его нет и там (multi-peer
медленнее обычного `rust`). Цели +30%/+60% не достигнуты.

**Что сделать.** Оставить режим выключенным по умолчанию; включать только для
замеров/multi-peer:

```sh
UMBRAWG_PARALLEL_RX=1 UMBRAWG_RX_WORKERS=3 UMBRAWG_RX_SCHED=peer \
  sudo -E umbrawg --foreground uwg0
```

Для сравнения «как есть» запустите без `UMBRAWG_PARALLEL_RX` и повторите тот
же iperf3. Не включать `UMBRAWG_RX_SCHED=queue` для продакшена: он даёт
большую суммарную скорость, но переставляет пакеты и вызывает ретрансмиты
TCP (в multipeer-прогоне — 40 828 ретрансмитов против 0 у `peer` при
`obf=0`).

**Как проверить.** Сравнить обычный и параллельный режим на одном и том же
пире и конфигурации; смотреть TCP-ретрансмиты (`Retr` в отчёте `iperf3`),
`uwg show <iface> transfer` и счётчики из 6.2:

```sh
iperf3 -c <peer-ip> -t 10 -P 1
iperf3 -c <peer-ip> -t 10 -P 10
uwg show uwg0 transfer
```

Ожидаемо: `peer` при `obf=0` не даёт лишних ретрансмитов на одном пире;
`queue` даёт ретрансмиты и нестабильный порядок. При `obf=1` ретрансмиты есть
и в однопоточном режиме (путь обфускации упирается в CPU стенда), поэтому
сравнивайте с запуском без `UMBRAWG_PARALLEL_RX`. Если параллельный режим на
одном пире медленнее — это документированное поведение, а не регрессия.

**Источник.** `umbrawg-rs/README.md` («Параллельный приём»,
«Производительность»); `docs/RESULTS.md` §5, §8; `umbrawg-rs/DESIGN.md`
(потоковая модель, `sched=peer`/`queue`).

### 6.2. `UMBRAWG_RX_SCHED`, глубина очереди и статистика

**Симптом.** Демон не стартует с `UMBRAWG_RX_QUEUE`; в логах растут
`drops(queue)`; непонятно, работает ли параллельный режим.

**Причина.** `UMBRAWG_RX_QUEUE` — степень двойки от 64 до 1024, иначе ошибка
старта (не clamp). Глубина задаёт память: слот до 64 КиБ, на воркера
`глубина × 64 КиБ` (256 → ~16 МиБ, 1024 → ~64 МиБ). Переполнение очереди
выбранного пиром воркера — дроп со счётчиком, задание не перекидывается,
чтобы не сломать порядок. `UMBRAWG_RX_STATS=1` печатает счётчики раз в 5 с.

**Что сделать.**

```sh
UMBRAWG_PARALLEL_RX=1 \
UMBRAWG_RX_WORKERS=3 \
UMBRAWG_RX_SCHED=peer \
UMBRAWG_RX_QUEUE=512 \
UMBRAWG_RX_STATS=1 \
  sudo -E umbrawg --foreground uwg0
```

Ожидаемо в логе при старте:

```text
parallel rx enabled: 3 crypto workers, sched=peer, queue depth 512 slots (~32 MiB per worker)
```

Раз в 5 секунд:

```text
rx stats: sched=peer datagrams=... enqueued=... controls=... control_drops=...
under_load=... segments=... gro_splits=... max_datagram_segments=...
mixed_peers=... housekeeping=... drops(detect=... prepared=... endpoint=...
queue=... size=... open=... replay=... allowed=... tun=... tx=... pool=...) wakes=...
```

Что означает:

| Счётчик | Что значит | Действие |
|---|---|---|
| `drops(queue)` | очередь выбранного воркера переполнена | увеличить `UMBRAWG_RX_QUEUE` (до 1024) или снизить всплеск; не менять `sched` на `queue` ради этого |
| `drops(prepared)` | пакет не подготовлен (drop на классификации/подготовке) | смотреть `UMBRAWG_LOG_LEVEL=debug`, проверить обфускацию/MTU |
| `drops(endpoint)` | `recvmsg` не вернул адрес отправителя | проверить сеть/сокет; это не ошибка конфигурации пира |
| `control_drops` | переполнена очередь управления (128) при флуде | проверить `under_load`, ограничить флуд на границе (firewall/rate limit); очередь всего 128 слотов |
| `mixed_peers` | в одной GRO-дейтаграмме разные пиры (аномалия) | учитывать при разборе, пакеты не теряются |
| `under_load=1` | сработал детектор флуда, включены cookie | ожидаемо под флудом; проверить, что данные идут |

Если `drops(queue)` растёт при нулевых потерях UDP/TCP и совпавшем sha256 —
это переполнение приёмной очереди под нагрузкой, а не потеря корректности
(так в e2e final4: `queue=43` при 0% потерь). Если растут `drops(tun)`/
`drops(tx)`, смотрите TUN и сеть.

**Как проверить.**

```sh
journalctl -u umbrawg@uwg0 -b | grep 'rx stats'
```

Ожидаемо: `sched` совпадает с заданным, `drops` нулевые или объяснимые,
`wakes` растут. `UMBRAWG_RX_WORKERS` по умолчанию — половина ядер, не больше
4; `UMBRAWG_THREADS` в параллельном режиме игнорируется. `UMBRAWG_RX_QUEUE`
вне диапазона/не степень двойки — ошибка старта, а не молчаливый clamp.

**Источник.** `umbrawg-rs/README.md` (переменные, «Глубина очереди и
память», счётчики); `umbrawg-rs/DESIGN.md` (SPSC, `queue`, `drops`);
`umbrawg-rs/crates/umbrawg/src/parallel.rs` (строка `rx stats`).

## 7. Отладка

### 7.1. Логи демона и модуля

**Демон.**

```sh
sudo UMBRAWG_LOG_LEVEL=debug umbrawg --foreground uwg0
```

или для systemd добавьте в `sudo systemctl edit umbrawg@uwg0`:

```ini
[Service]
Environment=UMBRAWG_LOG_LEVEL=debug
```

```sh
sudo systemctl restart umbrawg@uwg0
sudo journalctl -u umbrawg@uwg0 -b -f
```

Уровни: `trace`, `debug`, `info`, `warn`, `error` (по умолчанию `info`).
Перед foreground-запуском остановите юнит, иначе TUN/сокет будет занят.

**Модуль.** Включить dynamic debug и смотреть `dmesg`:

```sh
echo "module umbrawg +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
sudo dmesg -wT
```

Выключить обратно:

```sh
echo "module umbrawg -p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

**Что искать.** `ERROR`, `panicked`, `worker stopped`, `parallel rx failure`
(демон); `WARN`, `BUG`, `Call Trace`, `Key was rejected`, `unknown symbol`
(ядро).

**Источник.** `umbrawg-rs/README.md` (`UMBRAWG_LOG_LEVEL`);
`umbrawg-rs/crates/umbrawg/src/main.rs`; `umbrawg-linux-kernel-module/README.md`
(Troubleshooting → Enable debug logging).

### 7.2. Handshake, transfer, endpoints и счётчики

**Состояние интерфейса:**

```sh
uwg show uwg0
uwg show uwg0 latest-handshakes
uwg show uwg0 transfer
uwg show uwg0 endpoints
uwg show uwg0 allowed-ips
uwg show uwg0 public-key
uwg show uwg0 listen-port
uwg show uwg0 advanced-security
date +%s
```

Ожидаемо: `latest-handshakes` — epoch последнего handshake (0 — никогда),
`transfer` — два числа (rx/tx) на пира, `endpoints` — адрес или `(none)`,
`allowed-ips` — список или `(none)`. Старый handshake сам по себе не ошибка,
если по туннелю нет трафика; смотрите `transfer` и ping. Если handshake `0`
при наличии трафика — см. раздел 1.3.

**Пакеты и счётчики:**

```sh
sudo tcpdump -ni any -vv 'udp port 51820'
sudo nstat -az
sudo nstat -az | grep -Ei 'udp|frag|drop'
cat /proc/net/softnet_stat
ip -s link show dev uwg0
```

Что смотреть:

- `IpFragCreates`/`IpFragOKs` растут — фрагментация, раздел 2.1;
- `UdpRcvbufErrors` — приёмный буфер (iperf3/демон), раздел 2.3/2.4;
- `UdpInErrors` — ошибки приёма UDP;
- `time_squeeze` (третий столбец `/proc/net/softnet_stat`) — softirq не
  успевает, смотреть CPU/perf;
- `errors/dropped` на `uwg0` — дропы интерфейса;
- `FRAGMENTED`/`frag>0` в `.diag`/CSV стенда — фрагментация на подложке.

**Источник.** `crates/uwg/src/output.rs` (`latest-handshakes`, `transfer`,
`endpoints`, `advanced-security`); `umbrawg-linux-kernel-module/docs/PEER-SHARDING.md`
(что снимать: `ip -s link`, `softnet_stat`, `RcvbufErrors`);
`bench/README.md` (диагностика, CSV).

### 7.3. Профилирование

Для ядра и демона:

```sh
sysctl kernel.perf_event_paranoid      # для perf record -a нужно ≤1
sudo perf record -F 999 -g -a -- sleep 10
sudo perf report --stdio
```

Смотреть символы из плана проверки модуля: `__napi_poll`,
`napi_gro_receive`, `ip_rcv`, `tcp_v4_rcv`, `counter_validate`,
`uwg_reset_packet`, `chacha20poly1305_decrypt_sg_inplace`,
`process_one_work`, `queue_work_on`. Для пробуждений есть готовые скрипты
стенда:

```sh
sudo bash bench/wakeup-count.sh master 1
sudo bash bench/wakeup-profile.sh wakeup p1
```

Оба требуют root, `perf` с символами ядра и свободный стенд; они выгружают
`umbrawg`, ждут низкий load average и отсутствие `bn0`/`bn1`/чужих `iperf3`.

**Как проверить.** Профиль показывает, что доминирует: крипта, NAPI/GRO,
стек, `queue_work_on` или обфускация. Если ядра простаивают и нет
фрагментации, ищите не CPU, а MTU/GSO (2.1/2.2) и потери (2.4).

**Источник.** `bench/README.md` («Профилирование wakeup»);
`umbrawg-linux-kernel-module/docs/PEER-SHARDING.md` §6.2;
`umbrawg-rs/DESIGN.md` (профилирование).

### 7.4. Что приложить к отчёту о проблеме

- версии: `uwg --version`, `umbrawg --version`, `modinfo umbrawg`,
  `uname -r`;
- `uwg show <iface>` и `uwg showconf <iface>`;
- `ip -d link show dev <iface>`, `ip -s link show dev <iface>`,
  `ip route get <endpoint>`;
- `sysctl net.core.rmem_max net.core.wmem_max`;
- `nstat -az` до/после теста (дельты);
- логи: `journalctl -u umbrawg@<iface> -b` (с `UMBRAWG_LOG_LEVEL=debug`) или
  `dmesg` для модуля;
- для стенда: `.diag`, CSV, `RUN_ID`, `UNDERLAY_MTU`/`TUN_MTU`, `OBF`, версии
  бинарников (как в `docs/RESULTS.md` §1).

## 8. Ссылки

Документация:

- `README.md` — состав, сборка, использование, коды возврата, упаковка;
- `TODO.md` — известные проблемы и текущее состояние;
- `RELEASE.md` — порядок тегов, crates.io, AUR, deb/rpm;
- `docs/ARCHITECTURE.md` — компоненты, потоки, форматы, точки отказа;
- `docs/RESULTS.md` — матрица final4, GSO-фикс `obf=1` (§12), ограничения;
- `bench/README.md` — стенд, MTU-guard, GSO/veth, счётчики;
- `bench/PEER-SCALING.md` — масштабирование по пирам;
- `SECURITY.md` — приватный канал для уязвимостей;
- `CONTRIBUTING.md` — сборка, стиль, тесты.

Модуль ядра:

- `umbrawg-linux-kernel-module/README.md` — Linux 7.0+, `make LLVM=1`, DKMS,
  ограничения, Troubleshooting;
- `umbrawg-linux-kernel-module/docs/PERFORMANCE.md` — GSO, per-peer NAPI,
  UDP-потери, отклонённые изменения;
- `umbrawg-linux-kernel-module/docs/PEER-SHARDING.md` — приём по пирам,
  счётчики, план проверки;
- `umbrawg-linux-kernel-module/contrib/arch/README.md` — DKMS, MOK, AUR;
- код: `src/peer.c`, `src/receive.c`, `src/queueing.h`, `src/socket.c`,
  `src/device.c`, `src/netlink.c`.

Демон:

- `umbrawg-rs/README.md` — сборка, переменные, буферы, systemd, параллельный
  RX, data-plane e2e;
- `umbrawg-rs/DESIGN.md` — архитектура, потоки, обфускация, fast path;
- `umbrawg-rs/TODO.md` — известные проблемы;
- `umbrawg-rs/systemd/umbrawg@.service` — sandbox, capability, TUN;
- код: `crates/umbrawg/src/lib.rs`, `crates/umbrawg/src/parallel.rs`,
  `crates/umbrawg-uapi/src/listener.rs`, `crates/umbrawg-tun`.

Tools:

- `crates/uwg/src/{cli,main,output}.rs` — команды, коды возврата, вывод;
- `crates/uwg-quick/src/{main,commands,mtu,firewall,dns,usage}.rs` — root,
  MTU, DNS, firewall;
- `crates/umbrawg-ctl/src/{lib,uapi}.rs` — выбор транспорта, stale-сокет;
- `crates/umbrawg-config/src/{endpoint,model}.rs` — endpoint, INI, AllowedIPs;
- `bench/bench-lib.sh`, `bench/bench.sh` — MTU-guard, фрагментация, diag.

## 9. Границы документа

- Абсолютные цифры скорости — только для стенда из `docs/RESULTS.md`
  (6 vCPU, veth, MTU 9000); на реальном NIC и другом железе они другие.
- GSO/GRO на реальном NIC отдельно не измерялись: в документации модуля
  UDP GRO — гипотеза 2–4%, RSS/очереди реального NIC описаны только общими
  правилами.
- Демон обслуживает IPv4-транспорт; IPv6-подложка в него не подключена
  (`umbrawg-rs/README.md`, «Сеть»), хотя TUN и данные IPv6 поддерживают.
- ARM-сборки есть в CI, но рантайм на ARM-хостах не тестировался
  (`TODO.md` tools).
- Стабильные AUR-пакеты до первого тега заблокированы заглушкой
  `TODO_UPDPKGSUMS_AFTER_FIRST_TAG`; это ожидаемо, а не ошибка сборки.
- Порядок подписи и путь к MOK-ключу зависят от дистрибутива; документ
  ограничивается диагностикой (`mokutil`, `modinfo -F signer`, `dmesg`) и
  отсылкой к DKMS/MOK-документации дистрибутива.
