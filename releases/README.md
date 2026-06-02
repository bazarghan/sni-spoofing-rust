# Prebuilt Binaries

This folder contains the prebuilt binaries from the latest release, committed directly to the repository for users who cannot access the GitHub Releases page.

Current version: **v1.0.2**

| File | Platform |
|---|---|
| `sni-spoof-rs-linux-amd64` | Linux x86_64 |
| `sni-spoof-rs-linux-amd64-musl` | Linux x86_64 static musl |
| `sni-spoof-rs-linux-arm64` | Linux aarch64 |
| `sni-spoof-rs-macos-amd64` | macOS x86_64 |
| `sni-spoof-rs-macos-arm64` | macOS Apple Silicon |
| `sni-spoof-rs-ui-linux-amd64` | Linux desktop UI x86_64 |
| `sni-spoof-rs-ui-macos-amd64` | macOS desktop UI x86_64 |
| `sni-spoof-rs-ui-macos-arm64` | macOS desktop UI Apple Silicon |
| `sni-spoof-rs-ui-linux-amd64-bundle.tar.gz` | Linux desktop UI x86_64 plus Xray |
| `sni-spoof-rs-ui-macos-amd64-bundle.tar.gz` | macOS desktop UI x86_64 plus Xray |
| `sni-spoof-rs-ui-macos-arm64-bundle.tar.gz` | macOS desktop UI Apple Silicon plus Xray |
| `sni-spoof-rs-windows-amd64.zip` | Windows x86_64 (contains CLI, UI, Xray, Wintun, WinDivert.dll, WinDivert64.sys) |

## Download via git clone

```
git clone https://github.com/therealaleph/sni-spoofing-rust.git
cd sni-spoofing-rust/releases
```

## Download via zip

Go to [github.com/therealaleph/sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust), click the green **Code** button, then **Download ZIP**. Extract the zip, then the binaries are in the `releases/` folder.

## After download

On Linux/macOS, mark the binary executable:

```
chmod +x sni-spoof-rs-linux-amd64
sudo ./sni-spoof-rs-linux-amd64 config.json
```

On Windows, extract the zip (keep `.exe`, `.dll`, `.sys` together), then run as Administrator.

The desktop UI binaries must also run elevated because the packet proxy needs raw packet access:

```
chmod +x sni-spoof-rs-ui-linux-amd64
sudo ./sni-spoof-rs-ui-linux-amd64
```

The desktop UI can run the packet proxy and, for VLESS/Trojan links, a local Xray HTTP/HTTPS proxy plus SOCKS5 proxy. Paste one or more links, one config per line, download/select Xray if needed, then use **Start all-in-one**. Use `127.0.0.1:1080` as the HTTP/HTTPS proxy or `127.0.0.1:1081` as the SOCKS5 proxy. To share with other devices on the same trusted LAN, bind the UI proxy listeners to `0.0.0.0` and use this machine's LAN IP from the other device. Bundle archives include Xray beside the UI binary; **Download Xray** installs it into a persistent app data folder. On Windows it also installs `wintun.dll` for Xray TUN mode. Use **Fetch my IP** to verify the active proxy and turn off **Logging** if you do not want logs stored in the UI state file.

---

## فایل‌های اجرایی

این پوشه شامل فایل‌های اجرایی آخرین نسخه است که مستقیماً در ریپازیتوری قرار گرفته‌اند برای کاربرانی که به صفحه GitHub Releases دسترسی ندارند.

نسخه فعلی: **v1.0.2**

### دانلود از طریق ZIP

به [github.com/therealaleph/sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust) بروید، روی دکمه سبز **Code** کلیک کنید و **Download ZIP** را بزنید. پس از اکسترکت، فایل‌ها در پوشه `releases/` هستند.

### بعد از دانلود

در لینوکس/مک ابتدا اجرایی کنید:

```
chmod +x sni-spoof-rs-linux-amd64
sudo ./sni-spoof-rs-linux-amd64 config.json
```

در ویندوز zip را اکسترکت کنید (فایل‌های `.exe`، `xray.exe`، `wintun.dll`، `.dll` و `.sys` کنار هم باشند) و با Administrator اجرا کنید.

بسته‌های bundle لینوکس و مک، Xray را کنار فایل UI دارند. دکمه **Download Xray** هم آن را در مسیر دائمی داده‌های برنامه نصب می‌کند؛ در ویندوز `wintun.dll` لازم برای TUN را هم کنار Xray می‌گذارد. با **Fetch my IP** می‌توانید فعال بودن پروکسی را بررسی کنید و اگر نمی‌خواهید لاگ در فایل state ذخیره شود، گزینه **Logging** را خاموش کنید.
