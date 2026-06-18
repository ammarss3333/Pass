# Password Vault Pro for LilyGO T-Display-S3

An offline hardware password vault for the **ESP32-S3 LilyGO T-Display-S3**. The device stores credentials in an AES-256-GCM encrypted LittleFS vault, exposes a local-only Wi-Fi access point for management, and can type credentials through USB HID and Bluetooth HID.

> **Hardware target:** LilyGO T-Display-S3 standard non-touch model. PSRAM is intentionally disabled for stability across board batches.

## Features

- **Encrypted vault at rest** using AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation.
- **Offline management portal** hosted by the ESP32-S3 SoftAP at `http://192.168.4.1`.
- **Physical session password** displayed on the TFT at boot and required with the master PIN.
- **Decoy vault mode** for a separate, isolated vault protected by a different PIN.
- **USB and BLE credential injection** for username/password and TOTP workflows.
- **On-device navigation** with the two physical buttons.
- **Responsive web UI** with search, sorting, favorites, pagination, password generator, strength hints, and maintenance actions.
- **TOTP support** for Base32 secrets after browser time synchronization.

## Security Model

This project is designed for local, offline use. It is not a cloud password manager and should not be exposed to the internet.

Security controls include:

- Master PIN is never stored on disk.
- Vault records are encrypted before being written to LittleFS.
- Session cookies are `HttpOnly` and `SameSite=Strict`.
- HTTP responses use no-store cache headers and basic content-security headers.
- User-supplied fields are length-limited and sanitized before serialization.
- TOTP secrets are validated as Base32 before saving.
- Failed unlock attempts are delayed after repeated failures.
- Vaults created by older firmware using 50,000 PBKDF2 iterations are accepted and automatically rewritten with the current 120,000-iteration setting after a successful unlock.

Before production use:

1. Change `AP_PASS`, `BLE_NAME`, and `BLE_PASSKEY` in `PasswordVaultPro_OPTIMIZED.ino`.
2. Use a strong master PIN or passphrase of 6-64 characters.
3. Keep encrypted backups in multiple safe locations.
4. Enable destructive wipe only after backups and recovery have been tested.

## Hardware

| Component | Requirement |
| --- | --- |
| Board | LilyGO T-Display-S3 standard non-touch version |
| MCU | ESP32-S3 |
| Display | 1.9-inch ST7789 LCD over 8-bit parallel bus |
| Storage | Internal flash with LittleFS partition |
| USB | Native USB-C with CDC/JTAG and HID support |
| Buttons | GPIO 0 navigation, GPIO 14 type/inject |

### Pins

| Pin | Purpose |
| --- | --- |
| `15` | `PIN_POWER_ON`; must be driven HIGH on boot |
| `38` | TFT backlight |
| `0` | Navigation button |
| `14` | Type/inject button |

## Arduino IDE Configuration

Use these settings for the LilyGO T-Display-S3:

- **Board:** ESP32S3 Dev Module
- **USB Mode:** Hardware CDC and JTAG
- **USB CDC On Boot:** Enabled
- **Flash Mode:** DIO 80 MHz
- **Flash Size:** 16 MB (128 Mb)
- **Partition Scheme:** 8M with spiffs (3MB APP / 1.5MB SPIFFS)
- **PSRAM:** Disabled

## Dependencies

Install or enable the following libraries:

- ESP32 Arduino core with `WiFi`, `WebServer`, `DNSServer`, `LittleFS`, `Preferences`, `USB`, `USBHIDKeyboard`, and `mbedtls`.
- [`TFT_eSPI`](https://github.com/Bodmer/TFT_eSPI) by Bodmer.
- `ESP32-BLE-Keyboard` by T-vK.

## Required TFT_eSPI Setup

Configure `TFT_eSPI/User_Setup.h` for the LilyGO T-Display-S3 8-bit parallel display:

```cpp
#define USER_SETUP_ID 206
#define ST7789_DRIVER
#define INIT_SEQUENCE_3
#define CGRAM_OFFSET
#define TFT_RGB_ORDER TFT_BGR
#define TFT_INVERSION_ON
#define TFT_WIDTH  170
#define TFT_HEIGHT 320
#define TFT_PARALLEL_8_BIT
#define TFT_RST    5
#define TFT_CS     6
#define TFT_DC     7
#define TFT_WR     8
#define TFT_RD     9
#define TFT_D0     39
#define TFT_D1     40
#define TFT_D2     41
#define TFT_D3     42
#define TFT_D4     45
#define TFT_D5     46
#define TFT_D6     47
#define TFT_D7     48
#define TFT_BL     38
#define TFT_BACKLIGHT_ON HIGH
#define LOAD_GLCD
#define LOAD_FONT2
#define LOAD_FONT4
#define LOAD_FONT6
#define LOAD_FONT7
#define LOAD_FONT8
#define LOAD_GFXFF
#define SMOOTH_FONT
```

## Installation

1. Clone this repository.
2. Open `PasswordVaultPro_OPTIMIZED.ino` in Arduino IDE.
3. Update the configuration constants near the top of the file:
   - `AP_SSID`
   - `AP_PASS`
   - `BLE_NAME`
   - `BLE_PASSKEY`
   - optional lockout and wipe policy values
4. Confirm the Arduino IDE board settings listed above.
5. Compile and upload to the LilyGO T-Display-S3.
6. Reboot the device and verify the TFT shows the access point address and session password.

## Usage

1. Connect a phone or computer to the device Wi-Fi network.
2. Open `http://192.168.4.1`.
3. On first run, create the master PIN/passphrase.
4. On subsequent unlocks, enter both:
   - master PIN/passphrase
   - session password displayed on the physical screen
5. Add credentials from the web UI.
6. Use search, sort, favorites, and pagination to navigate larger vaults.
7. Press the device type button to inject the selected credential. For entries with TOTP, the first press types the password and the second press types the current TOTP code.

## Web UI Navigation

The vault UI avoids long scrolling by combining:

- **Search** for filtering labels and usernames.
- **Sort modes** for smart favorites-first ordering, A-Z, Z-A, and weak-password-first review.
- **Pagination** with 12 visible records per page, keeping the interface fast on mobile devices and within ESP32 memory limits.
- **Favorites and grouped sections** for quick access to high-priority credentials.

## Internal File Layout

LittleFS paths used by the firmware:

| Path | Purpose |
| --- | --- |
| `/vault.bin` | Primary encrypted vault |
| `/decoy.bin` | Decoy encrypted vault |
| `/vault.bak` | Reserved backup path |
| `/vault.tmp` | Reserved temporary upload path |
| `/import.csv` | Reserved temporary import path |

## Limitations

- Intended capacity is approximately 200 credentials.
- The local web portal uses HTTP because it runs on a SoftAP microcontroller; do not bridge or expose the AP to untrusted networks.
- Browser clipboard APIs may require a secure context on some platforms; manual reveal remains available.
- TOTP requires opening the web UI once after boot so browser time can sync to the device.

## Contributing

Contributions should preserve the offline-first threat model and ESP32-S3 memory constraints.

When contributing:

- Keep PSRAM disabled unless a separate hardware-specific build is documented.
- Avoid large dynamic buffers and long-lived plaintext copies.
- Do not add cloud synchronization or external network dependencies.
- Validate all user input and avoid exposing sensitive diagnostics to the web UI.
- Test on the LilyGO T-Display-S3 standard non-touch board before submitting changes.

## License

Add your preferred license before distributing this project publicly.
