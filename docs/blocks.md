# DPI GUI — заметки по блокам (базис знаний)

> Файл для технических фактов и «узлов встречи» смежных подсистем. Пунктов
> Spirit: фиксировать решения с обоснованием, чтобы не спорить по кругу.

## 1. DNS: системные адреса (Windows)

На Windows `from_system_conf()` корректен. Он не «угадывает» адрес, а читает те же
адаптеры через `ipconfig::get_adapters()`, но за счёт встроенного TCP-fallback
оказывается устойчивее голого nslookup. У пользователя в РФ, где TCP:53 часто
заблокирован полностью или оба протокола возвращают одинаковый ответ от ТСПУ,
`from_system_conf()` получит именно подменённый адрес. Менять `from_system_conf()`
на вызовы `cmd /c nslookup` было бы антипаттерном (§3.9) — текущий код на
trust-dns правилен.

## 2. DoH-сервисы: источники списков (SSOT-файл)

Список используемых DoH-резолверов живёт в
`src-tauri/defaults/doh-services.txt` (см. AGENTS.md §4.2: при каждом старте
копируется в `AppData/Roaming/DPI_GUI/defaults/doh-services.txt`). Формат файлов:
полный URL (`https://host/dns-query`) или только хост; комментарии `#` игнорируются.

> **ВАЖНО (РКН/ТСПУ):** ТСПУ банит IP-адреса DNS-серверов. Поэтому серверы из
> списков могут НЕ отвечать у пользователя, пока не добавлены в обход (winws).
> Не используйте «сервер не пингуется» как критий добавления в файл: проверку
> живости проводить только при включённом обходе (tests `live_doh_resolvers_*`
> в `site_probe.rs` игнорируются без сети по этой же причине).

### 2.1 Справочные источники
1. **AdGuard DNS KB — «Известные DNS-провайдеры»**
   https://adguard-dns.io/kb/ru/general/dns-providers/
   (таблица протоколов по провайдерам: IPv4/IPv6/DoH/DoT/DoQ/DNSCrypt;
   выбирать ВНИМАТЕЛЬНО unfiltered-варианты — фильтрующие ломают «тест подмены
   DNS»: часть доменов просто не резолвится).
2. **DNSCrypt — Public DNSCrypt & DoH Servers List**
   https://dnscrypt.info/public-servers/
   (страница рендерится с GitHub-репозитория
   https://github.com/dnscrypt/dnscrypt-resolvers — то же самое в markdown).

### 2.2 Хосты, добавленные из этих источников (23.10.2026)
В файл добавлены только unfiltered / без-логов публичные anycast-резолверы
(основание — 1 и 2 выше): `unfiltered.adguard-dns.com`, `cloudflare-dns.com`,
`dns.google`, `doh.sandbox.opendns.com` (OpenDNS Sandbox, unfiltered), `doh.dns.sb`,
`dns10.quad9.net` (unfiltered), `wikimedia-dns.org`, `doh.libredns.gr`,
`unfiltered.joindns4.eu` (DNS4EU, unfiltered), `dns.digitale-gesellschaft.ch`,
`dns.decloudus.com`. Итого 19 валидных строк (8 RU-специфичных + 11 глобальных).

Не добавлены намеренно:
- **ControlD** (`freedns.controld.com/p0`) — НЕСОВМЕСТИМ с нашим парсером:
  `parse_doh_services` отбрасывает путь, а запрос всегда идёт на
  `https://{host}/dns-query` (см. `main.rs:68`), кастомный path `/p0` потеряется.
  Если когда-нибудь понадобится — сначала менять формат файла парсер+путей.
- Китайские (`doh.360.cn`, `dns.alidns.com`, `dns.pub`) — гео-фон РФ бессмыслен.
- Фильтрующие варианты (`family.*`, `security.*`, `p1..p3`, `internetsehat`,
  `dns11.quad9.net`, Quad9 `dns.quad9.net` 9.9.9.9 = malware-фильтр) — для
  «теста подмены DNS» нужна нейтральность.
- `dns.nextdns.io` — без ID-профиля режет рекламу по умолчанию.
