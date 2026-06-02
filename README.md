# sni-spoof-rs

[![Release](https://img.shields.io/github/v/release/therealaleph/sni-spoofing-rust)](https://github.com/therealaleph/sni-spoofing-rust/releases/latest)
[![Total Downloads](https://img.shields.io/github/downloads/therealaleph/sni-spoofing-rust/total?label=total%20downloads)](https://github.com/therealaleph/sni-spoofing-rust/releases)
[![Latest Downloads](https://img.shields.io/github/downloads/therealaleph/sni-spoofing-rust/latest/total?label=latest%20release)](https://github.com/therealaleph/sni-spoofing-rust/releases/latest)
[![Stars](https://img.shields.io/github/stars/therealaleph/sni-spoofing-rust?style=flat)](https://github.com/therealaleph/sni-spoofing-rust/stargazers)
[![License](https://img.shields.io/github/license/therealaleph/sni-spoofing-rust)](LICENSE)

Rust implementation of [patterniha's SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass technique. Credit for the original method goes to [@patterniha](https://github.com/patterniha).

sni-spoof-rs is a local TCP forwarder and desktop helper for Cloudflare-fronted VLESS/VMess/Trojan/Xray-style configs. It injects a fake TLS ClientHello with an intentionally wrong TCP sequence number immediately after the TCP handshake. Passive DPI sees the fake SNI and may whitelist the flow; the real server drops that fake packet because it is outside the receive window; then the real TLS traffic passes normally.

**[English Guide](#english-guide)** | **[راهنمای فارسی](#راهنمای-فارسی)**

## English Guide

### What You Get

- Native CLI proxy for Linux, macOS, and Windows.
- Native desktop UI for Linux, macOS, and Windows.
- Built-in Xray launcher for VLESS and Trojan links.
- Bundled UI packages that include the matching Xray binary next to the app.
- HTTP/HTTPS proxy on `127.0.0.1:1080` and SOCKS5 proxy on `127.0.0.1:1081`.
- LAN sharing mode using `0.0.0.0` so phones or other devices on the same trusted network can use the connection.
- Built-in fake-SNI scanner for finding domains that still pass on your ISP.
- Public IP check through the local proxy, so the UI can show whether the tunnel is actually working.
- Optional log persistence toggle for users who do not want logs written to the UI state file.
- Experimental Xray TUN inbound mode for elevated desktop runs.
- Docker image for running one shared proxy box for a local network.
- GitHub Actions release builds for Linux, macOS, Windows, and GHCR Docker images.

### Platform Requirements

This tool must touch raw packets. Normal user permissions are not enough for proxy mode.

| Platform | Requirement |
|---|---|
| Linux | Run as root, or grant `CAP_NET_RAW`/needed network capabilities |
| macOS | Run with `sudo` so BPF devices can be opened |
| Windows | Run as Administrator; keep WinDivert files next to the executable |

Scanner mode does not need root/admin because it only opens normal outbound TLS sockets.

### Download

Prebuilt binaries are available from:

- [GitHub Releases](https://github.com/therealaleph/sni-spoofing-rust/releases/latest)
- The [`releases/`](releases/) folder, for users who can clone/download the repo but cannot open the Releases page

The release assets include:

| File | Platform |
|---|---|
| `sni-spoof-rs-linux-amd64` | Linux x86_64 CLI |
| `sni-spoof-rs-linux-amd64-musl` | Linux x86_64 static musl CLI for older distros |
| `sni-spoof-rs-linux-arm64` | Linux aarch64 CLI |
| `sni-spoof-rs-macos-amd64` | macOS Intel CLI |
| `sni-spoof-rs-macos-arm64` | macOS Apple Silicon CLI |
| `sni-spoof-rs-ui-linux-amd64` | Linux x86_64 desktop UI |
| `sni-spoof-rs-ui-macos-amd64` | macOS Intel desktop UI |
| `sni-spoof-rs-ui-macos-arm64` | macOS Apple Silicon desktop UI |
| `sni-spoof-rs-ui-linux-amd64-bundle.tar.gz` | Linux x86_64 desktop UI plus Xray |
| `sni-spoof-rs-ui-macos-amd64-bundle.tar.gz` | macOS Intel desktop UI plus Xray |
| `sni-spoof-rs-ui-macos-arm64-bundle.tar.gz` | macOS Apple Silicon desktop UI plus Xray |
| `sni-spoof-rs-windows-amd64.zip` | Windows CLI, UI, Xray, Wintun, and WinDivert files |

### Fastest Path: Desktop UI

The UI is the easiest way to use the project with VLESS/Trojan links.

```bash
cargo build --release --features ui --bin sni-spoof-rs-ui
sudo ./target/release/sni-spoof-rs-ui
```

On Windows, run `sni-spoof-rs-ui.exe` as Administrator.

In the UI:

1. Paste one or more `vless://...` or `trojan://...` links in **Xray Import**, one config per line.
2. Pick the active config from the dropdown.
3. Press **Parse selected**. The UI resolves the real Cloudflare upstream and fills `connect`.
4. Press **Start all-in-one**.
5. Configure your browser or app:
   - HTTP/HTTPS proxy: `127.0.0.1:1080`
   - SOCKS5 proxy: `127.0.0.1:1081`
6. Press **Fetch my IP** or **Check IP** to verify that traffic exits through the local proxy.

If your pasted link already points to `127.0.0.1:40443`, the UI accepts it and resolves the real upstream from `host=` or `sni=`. This matches links generated for other local proxy apps.

If you use a `*-bundle.tar.gz` UI package or the Windows zip, keep `xray`/`xray.exe` beside the UI executable; the app will discover it automatically. The **Download Xray** button installs Xray into a persistent app data folder and updates `xray_binary`, so it stays available after restart instead of living in a temporary directory.

The UI saves form values, imported links, selected config, theme, scanner settings, and recent logs in `sni-spoof-rs-ui-state.json` next to the executable. Set `SNI_SPOOF_UI_STATE=/path/to/state.json` to use another location. Logs are persistent and can be exported from the Logs panel. Turn off **Logging** in the Logs panel if you do not want new logs kept in memory or written to the state file.

The **Xray TUN mode** checkbox adds an experimental Xray TUN inbound. Run elevated, keep HTTP/SOCKS enabled while testing, and watch for routing loops if another VPN/TUN client is already active. On Windows, `wintun.dll` must be beside `xray.exe`; the Windows zip and **Download Xray** button install it automatically.

### Sharing With Other Devices

Use this only on a trusted local network.

In the UI, press **Share on LAN**. It sets:

- Xray HTTP/HTTPS proxy: `0.0.0.0:1080`
- Xray SOCKS5 proxy: `0.0.0.0:1081`
- SNI listener: `0.0.0.0:40443`

Then set your phone or another device to use your computer's LAN IP, for example:

- HTTP/HTTPS proxy: `192.168.1.20:1080`
- SOCKS5 proxy: `192.168.1.20:1081`

Make sure your OS firewall allows inbound connections to those ports.

### Manual CLI Setup

Use CLI mode when you want to integrate with another v2ray/xray client yourself.

#### Step 1: Find the Cloudflare IP

Your config usually has a server domain like `myserver.example.com`. Resolve it:

```bash
nslookup myserver.example.com
```

You should get a Cloudflare IP, often in ranges such as `104.*`, `172.67.*`, `188.114.*`, `162.159.*`, or `141.101.*`.

#### Step 2: Create `config.json`

```json
{
  "graceful_shutdown_sec": 0,
  "listeners": [
    {
      "listen": "127.0.0.1:40443",
      "connect": "CLOUDFLARE_IP:443",
      "fake_sni": "security.vercel.com",
      "conn_timeout_sec": 5,
      "handshake_timeout_sec": 2,
      "keepalive_time_sec": 11,
      "keepalive_interval_sec": 2
    }
  ]
}
```

Replace `CLOUDFLARE_IP` with the resolved IP.

| Field | Description |
|---|---|
| `listen` | Local address and port where sni-spoof-rs accepts client connections |
| `connect` | Cloudflare IP and port to forward to; use an IP, not a hostname |
| `fake_sni` | Fake SNI inserted into the intentionally invalid ClientHello |
| `conn_timeout_sec` | Upstream TCP connect timeout |
| `handshake_timeout_sec` | Time to wait for the fake packet ACK confirmation |
| `keepalive_time_sec` | Idle time before TCP keepalive starts |
| `keepalive_interval_sec` | Time between TCP keepalive probes |
| `idle_timeout` | Optional top-level timeout for idle relays |
| `buffer_size` | Top-level relay buffer size in KiB |
| `graceful_shutdown_sec` | Top-level shutdown drain time; `0` exits immediately |

Multiple listeners are supported. Each listener maps one local port to one upstream.

#### Step 3: Rewrite Your Client Address

In your v2ray/xray client config, change only the server address and port:

- Address: `127.0.0.1`
- Port: `40443`

Keep UUID/password, SNI, host, path, transport type, TLS settings, fingerprint, and other fields unchanged.

#### Step 4: Run

```bash
# Linux/macOS
sudo ./sni-spoof-rs config.json

# Windows, from an Administrator terminal
sni-spoof-rs.exe config.json
```

Then connect your v2ray/xray client as usual.

### Docker Shared Proxy

The Docker image runs sni-spoof-rs and Xray together as shared HTTP/HTTPS and SOCKS5 proxies.

```bash
docker build -f docker/Dockerfile -t sni-spoof-proxy .

docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -p 1081:1081 \
  -e VLESS_URI='vless://your-full-link-here' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

Use:

- HTTP/HTTPS proxy: `<docker-host-ip>:1080`
- SOCKS5 proxy: `<docker-host-ip>:1081`

Check:

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
curl --socks5-hostname 127.0.0.1:1081 https://icanhazip.com
docker logs snispoof
```

### Finding a Working `fake_sni`

If your current `fake_sni` stops working, run the scanner:

```bash
./sni-spoof-rs scan
./sni-spoof-rs scan -o working.txt
./sni-spoof-rs scan --target 172.67.139.236:443
./sni-spoof-rs scan --concurrency 30 --timeout 4
```

Pick an `ok` result and put it in `fake_sni`.

The scanner only tests reachability of candidate fake SNIs. It does not guarantee that every ISP, route, or server config will work. If your ISP performs full TLS MITM instead of passive SNI filtering, this bypass may not be enough.

### Logging and Debugging

Default logs are quiet. For more detail:

```bash
sudo RUST_LOG=info ./sni-spoof-rs config.json
sudo RUST_LOG=debug ./sni-spoof-rs config.json
```

Useful log lines:

- `fake ClientHello injected`: packet injection happened.
- `server ACK confirmed, fake was ignored`: upstream ignored the fake packet and relay can start.
- `timeout waiting for fake ACK`: packet injection or packet capture did not confirm in time.
- `Connection reset by peer`: upstream or Xray closed the connection.

On macOS, if the route goes through a `utun` interface, the tool detects and parses the `utun` BPF packet header directly.

### Build From Source

```bash
cargo build --release
cargo build --release --features ui --bin sni-spoof-rs-ui
```

For local cross-platform builds:

```bash
make all
make ui
```

GitHub Actions builds and publishes release assets when a `v*` tag is pushed. Docker images are published to GHCR on release tags.

### How It Works

1. The client connects to the local listener.
2. sni-spoof-rs dials the Cloudflare upstream.
3. A sniffer records the TCP initial sequence number and the final ACK of the TCP handshake.
4. The injector sends a fake TLS ClientHello with `seq = ISN + 1 - len(fake)`.
5. Passive DPI reads the fake SNI.
6. The real server drops the fake packet because it is outside the receive window.
7. sni-spoof-rs waits for an ACK proving the fake was ignored.
8. The real TLS handshake and relay continue normally.

## راهنمای فارسی

### این ابزار چیست؟

sni-spoof-rs یک ابزار Rust برای دور زدن DPI مبتنی بر SNI است. ابزار یک ClientHello جعلی با SNI دلخواه می‌فرستد، اما شماره sequence آن را عمدا اشتباه می‌گذارد. DPI غیرفعال معمولا همان SNI جعلی را می‌بیند، ولی سرور واقعی آن پکت را دور می‌اندازد و ترافیک اصلی TLS بدون تغییر ادامه پیدا می‌کند.

این ابزار برای کانفیگ‌های پشت Cloudflare مناسب است؛ مخصوصا VLESS/VMess/Trojan/Xray که از CDN عبور می‌کنند.

### امکانات

- نسخه CLI برای Linux، macOS و Windows.
- رابط گرافیکی دسکتاپ برای Linux، macOS و Windows.
- اجرای داخلی Xray برای لینک‌های VLESS و Trojan.
- بسته‌های UI آماده که Xray مناسب همان سیستم را کنار برنامه دارند.
- پروکسی HTTP/HTTPS روی `127.0.0.1:1080`.
- پروکسی SOCKS5 روی `127.0.0.1:1081`.
- حالت اشتراک در شبکه محلی با `0.0.0.0` برای استفاده گوشی یا دستگاه‌های دیگر.
- اسکنر داخلی برای پیدا کردن `fake_sni` قابل استفاده روی ISP شما.
- چک کردن IP عمومی از داخل پروکسی برای فهمیدن اینکه اتصال واقعا برقرار شده یا نه.
- امکان خاموش کردن ذخیره لاگ برای کسانی که نمی‌خواهند لاگ در فایل state نوشته شود.
- حالت آزمایشی Xray TUN برای اجرای دسکتاپ با دسترسی بالا.
- نسخه Docker برای راه‌اندازی یک پروکسی مشترک روی یک سیستم.
- ساخت خودکار فایل‌های Release و Docker image با GitHub Actions.

### نیازمندی دسترسی

حالت proxy باید به پکت‌های خام دسترسی داشته باشد؛ بنابراین اجرای عادی کافی نیست.

| سیستم عامل | نیازمندی |
|---|---|
| Linux | اجرا با root یا capabilityهای لازم مثل `CAP_NET_RAW` |
| macOS | اجرا با `sudo` برای باز کردن BPF device |
| Windows | اجرا با Administrator و وجود فایل‌های WinDivert کنار برنامه |

حالت scan نیازی به root یا Administrator ندارد.

### دانلود

فایل‌های آماده از این دو مسیر قابل دریافت هستند:

- [GitHub Releases](https://github.com/therealaleph/sni-spoofing-rust/releases/latest)
- پوشه [`releases/`](releases/) داخل همین ریپازیتوری، برای وقتی که صفحه Releases باز نمی‌شود

فایل‌های مهم:

| فایل | پلتفرم |
|---|---|
| `sni-spoof-rs-linux-amd64` | نسخه CLI لینوکس x86_64 |
| `sni-spoof-rs-linux-amd64-musl` | نسخه CLI لینوکس x86_64 با musl برای توزیع‌های قدیمی‌تر |
| `sni-spoof-rs-linux-arm64` | نسخه CLI لینوکس aarch64 |
| `sni-spoof-rs-macos-amd64` | نسخه CLI مک Intel |
| `sni-spoof-rs-macos-arm64` | نسخه CLI مک Apple Silicon |
| `sni-spoof-rs-ui-linux-amd64` | رابط گرافیکی لینوکس x86_64 |
| `sni-spoof-rs-ui-macos-amd64` | رابط گرافیکی مک Intel |
| `sni-spoof-rs-ui-macos-arm64` | رابط گرافیکی مک Apple Silicon |
| `sni-spoof-rs-ui-linux-amd64-bundle.tar.gz` | رابط گرافیکی لینوکس x86_64 همراه Xray |
| `sni-spoof-rs-ui-macos-amd64-bundle.tar.gz` | رابط گرافیکی مک Intel همراه Xray |
| `sni-spoof-rs-ui-macos-arm64-bundle.tar.gz` | رابط گرافیکی مک Apple Silicon همراه Xray |
| `sni-spoof-rs-windows-amd64.zip` | نسخه ویندوز شامل CLI، UI، Xray، Wintun و WinDivert |

### راه سریع: رابط گرافیکی

برای اکثر کاربران، UI ساده‌ترین راه است.

```bash
cargo build --release --features ui --bin sni-spoof-rs-ui
sudo ./target/release/sni-spoof-rs-ui
```

در ویندوز، فایل `sni-spoof-rs-ui.exe` را با Administrator اجرا کنید.

مراحل:

1. در بخش **Xray Import** یک یا چند لینک `vless://...` یا `trojan://...` را وارد کنید. هر لینک در یک خط.
2. کانفیگ فعال را از لیست انتخاب کنید.
3. روی **Parse selected** بزنید تا IP واقعی Cloudflare پیدا شود و فیلد `connect` پر شود.
4. روی **Start all-in-one** بزنید.
5. در مرورگر یا اپ خود پروکسی را تنظیم کنید:
   - HTTP/HTTPS: `127.0.0.1:1080`
   - SOCKS5: `127.0.0.1:1081`
6. با **Fetch my IP** یا **Check IP** بررسی کنید که خروجی اینترنت از همین پروکسی انجام می‌شود.

اگر لینک شما از قبل به `127.0.0.1:40443` اشاره می‌کند، UI آن را قبول می‌کند و مقصد واقعی را از `host=` یا `sni=` پیدا می‌کند.

اگر بسته‌های `*-bundle.tar.gz` یا zip ویندوز را استفاده کنید، فایل `xray` یا `xray.exe` کنار برنامه قرار دارد و UI آن را خودکار پیدا می‌کند. دکمه **Download Xray** هم Xray را در پوشه دائمی داده‌های برنامه نصب می‌کند و مسیر `xray_binary` را تنظیم می‌کند؛ بنابراین بعد از ری‌استارت هم باقی می‌ماند.

UI تنظیمات فرم، لینک‌های وارد شده، کانفیگ انتخاب شده، تم، تنظیمات اسکنر و لاگ‌های اخیر را در فایل `sni-spoof-rs-ui-state.json` کنار برنامه ذخیره می‌کند. برای تغییر مسیر ذخیره‌سازی، متغیر `SNI_SPOOF_UI_STATE=/path/to/state.json` را تنظیم کنید. لاگ‌ها ماندگار هستند و از پنل Logs قابل خروجی گرفتن هستند. اگر نمی‌خواهید لاگ جدید در حافظه یا فایل state ذخیره شود، گزینه **Logging** را در پنل Logs خاموش کنید.

گزینه **Xray TUN mode** یک inbound آزمایشی TUN به Xray اضافه می‌کند. برنامه را با دسترسی بالا اجرا کنید، هنگام تست HTTP/SOCKS را هم روشن نگه دارید، و اگر VPN/TUN دیگری فعال است مراقب loop شدن routeها باشید. در ویندوز، فایل `wintun.dll` باید کنار `xray.exe` باشد؛ zip ویندوز و دکمه **Download Xray** آن را خودکار نصب می‌کنند.

### استفاده برای دستگاه‌های دیگر شبکه

این حالت را فقط در شبکه محلی قابل اعتماد استفاده کنید.

در UI روی **Share on LAN** بزنید. این کار مقادیر زیر را تنظیم می‌کند:

- پروکسی HTTP/HTTPS: `0.0.0.0:1080`
- پروکسی SOCKS5: `0.0.0.0:1081`
- لیسنر SNI: `0.0.0.0:40443`

بعد روی گوشی یا دستگاه دیگر، IP شبکه محلی کامپیوتر خود را وارد کنید. مثلا:

- HTTP/HTTPS: `192.168.1.20:1080`
- SOCKS5: `192.168.1.20:1081`

اگر فایروال سیستم فعال است، پورت‌ها را باز کنید.

### راه‌اندازی دستی با CLI

#### مرحله ۱: پیدا کردن IP کلادفلر

دامنه سرور کانفیگ خود را resolve کنید:

```bash
nslookup myserver.example.com
```

باید یک IP مربوط به Cloudflare بگیرید؛ مثلا رنج‌هایی مثل `104.*`، `172.67.*`، `188.114.*`، `162.159.*` یا `141.101.*`.

#### مرحله ۲: ساخت `config.json`

```json
{
  "graceful_shutdown_sec": 0,
  "listeners": [
    {
      "listen": "127.0.0.1:40443",
      "connect": "IP_CLOUDFLARE:443",
      "fake_sni": "security.vercel.com",
      "conn_timeout_sec": 5,
      "handshake_timeout_sec": 2,
      "keepalive_time_sec": 11,
      "keepalive_interval_sec": 2
    }
  ]
}
```

به جای `IP_CLOUDFLARE` همان IP مرحله قبل را بگذارید.

| فیلد | توضیح |
|---|---|
| `listen` | آدرس و پورتی که برنامه روی آن اتصال محلی می‌گیرد |
| `connect` | IP و پورت Cloudflare؛ بهتر است IP باشد نه دامنه |
| `fake_sni` | SNI جعلی که در ClientHello نامعتبر قرار می‌گیرد |
| `conn_timeout_sec` | زمان انتظار برای اتصال TCP به مقصد |
| `handshake_timeout_sec` | زمان انتظار برای تایید ACK پکت جعلی |
| `keepalive_time_sec` | زمان بیکاری قبل از شروع TCP keepalive |
| `keepalive_interval_sec` | فاصله بین keepalive probeها |
| `idle_timeout` | مقدار اختیاری در سطح اصلی برای قطع اتصال بیکار |
| `buffer_size` | اندازه بافر relay بر حسب KiB |
| `graceful_shutdown_sec` | زمان انتظار هنگام خاموش شدن؛ مقدار `0` یعنی خروج سریع |

می‌توانید چند listener داشته باشید؛ هر listener یک پورت محلی را به یک مقصد وصل می‌کند.

#### مرحله ۳: تغییر کانفیگ کلاینت

در کلاینت v2ray/xray فقط آدرس و پورت سرور را تغییر دهید:

- Address: `127.0.0.1`
- Port: `40443`

بقیه موارد مثل UUID/password، SNI، host، path، نوع transport، TLS و fingerprint را تغییر ندهید.

#### مرحله ۴: اجرا

```bash
# Linux/macOS
sudo ./sni-spoof-rs config.json

# Windows با دسترسی Administrator
sni-spoof-rs.exe config.json
```

بعد کلاینت v2ray/xray خود را مثل همیشه وصل کنید.

### Docker برای پروکسی مشترک

Docker هم sni-spoof-rs و هم Xray را اجرا می‌کند و دو پروکسی HTTP/HTTPS و SOCKS5 می‌دهد.

```bash
docker build -f docker/Dockerfile -t sni-spoof-proxy .

docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -p 1081:1081 \
  -e VLESS_URI='vless://لینک-کامل-شما' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

روی دستگاه‌ها:

- HTTP/HTTPS: `<IP-سیستم-داکر>:1080`
- SOCKS5: `<IP-سیستم-داکر>:1081`

تست:

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
curl --socks5-hostname 127.0.0.1:1081 https://icanhazip.com
docker logs snispoof
```

### پیدا کردن `fake_sni` مناسب

اگر `fake_sni` فعلی کار نکرد، اسکنر را اجرا کنید:

```bash
./sni-spoof-rs scan
./sni-spoof-rs scan -o working.txt
./sni-spoof-rs scan --target 172.67.139.236:443
./sni-spoof-rs scan --concurrency 30 --timeout 4
```

یکی از نتایج `ok` را در `fake_sni` بگذارید.

اسکنر فقط در دسترس بودن SNIهای کاندید را تست می‌کند. اگر ISP شما TLS MITM کامل انجام دهد، این روش ممکن است کافی نباشد.

### لاگ و عیب‌یابی

برای لاگ بیشتر:

```bash
sudo RUST_LOG=info ./sni-spoof-rs config.json
sudo RUST_LOG=debug ./sni-spoof-rs config.json
```

معنی چند لاگ مهم:

- `fake ClientHello injected`: تزریق پکت جعلی انجام شده.
- `server ACK confirmed, fake was ignored`: سرور پکت جعلی را نادیده گرفته و relay شروع می‌شود.
- `timeout waiting for fake ACK`: تزریق یا کپچر پکت تایید نشده.
- `Connection reset by peer`: مقصد یا Xray اتصال را بسته است.

### ساخت از سورس و CI/CD

```bash
cargo build --release
cargo build --release --features ui --bin sni-spoof-rs-ui
make all
make ui
```

با push کردن tag مثل `v1.0.1`، GitHub Actions فایل‌های Linux/macOS/Windows را می‌سازد، Release می‌سازد، فایل‌ها را به Release اضافه می‌کند و Docker image را هم در GHCR منتشر می‌کند.

## License

MIT
