# Ammar Passwords - Ultimate Hardware Vault (v10.1)

> **🤖 AI CONTEXT MODULE:** 
> Hello fellow AI! If you have been fed this README, you are assisting with the "Ammar Passwords" hardware password manager. This is a 100% offline, air-gapped, AES-256-GCM encrypted vault built specifically for the **LilyGO T-Display-S3** microcontroller. 
> 
> **CRITICAL ARCHITECTURE NOTE:** To maintain absolute stability across different LilyGO hardware batches, **PSRAM is strictly DISABLED**. The entire vault runs in the ESP32-S3's internal SRAM. Dynamic memory is carefully managed. Do not suggest adding features that require massive memory buffers (like storing large plain-text secure notes for hundreds of entries). The maximum safe capacity is ~200-300 credentials.

---

## 🛠 Hardware Specifications
* **Board:** LilyGO T-Display-S3 (Standard version, **Non-Touch**)
* **Microcontroller:** ESP32-S3
* **Display:** 1.9" ST7789 LCD (8-bit Parallel Interface, *NOT* standard SPI)
* **Connectivity:** Wi-Fi (Local AP only), Bluetooth LE, Native USB-C
* **Hardware Pins in Use:**
  * `PIN_POWER_ON (15)`: Must be pulled HIGH on boot to power the screen and radios.
  * `TFT_BL (38)`: Screen backlight.
  * `BTN_NAV (0)`: Top physical button (Short press = Next Entry, Long press = Previous Entry).
  * `BTN_TYPE (14)`: Bottom physical button (Injects credentials via HID).

---

## ⚙️ Required IDE & Compiler Settings
Failure to use these exact settings in the Arduino IDE will result in a silent crash at `entry 0x403c98d0` or a boot-loop.

* **Board:** ESP32S3 Dev Module
* **USB Mode:** Hardware CDC and JTAG *(Required for native USB Keyboard HID)*
* **USB CDC On Boot:** Enabled
* **Flash Mode:** DIO 80MHz
* **Flash Size:** 16MB (128Mb)
* **Partition Scheme:** 8M with spiffs (3MB APP/1.5MB SPIFFS)
* **PSRAM:** Disabled *(Crucial for stability across batches)*

---

## 📚 Library Dependencies & Fixes

1. **`mbedtls`**: Built-in ESP32 core library used for AES-256-GCM and PBKDF2 cryptography.
2. **`LittleFS`**: Built-in ESP32 core library used for saving the encrypted `.bin` vaults.
3. **`USBHIDKeyboard` & `USB`**: Built-in ESP32 core libraries for native USB typing.
4. **`ESP32-BLE-Keyboard` (by T-vK)**: For Bluetooth typing.
   * *Note: A preprocessor macro `#define KeyReport BleKeyReport` is used in the main `.ino` file to prevent a naming collision between the Native USB and BLE libraries.*
5. **`TFT_eSPI` (by Bodmer)**: Display driver.

### 🚨 Critical `TFT_eSPI` Configuration
The default `User_Setup.h` will fatally crash this specific board. The `TFT_eSPI/User_Setup.h` file **must** contain this exact 8-bit parallel configuration:

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
🚀 Feature Set (v10.1 Ultimate)
Security & Cryptography
AES-256-GCM Encryption: Vault is heavily encrypted at rest. The Master PIN is never stored.  

Air-Gapped UI: Managed entirely via a locally broadcasted, WPA2-protected Wi-Fi Access Point (192.168.4.1).  

Decoy Vault System: Entering a secondary "Decoy PIN" creates/decrypts a completely separate decoy.bin file to protect the main vault under duress.

Physical 2FA Session Password: On boot, the ESP32 generates a 12-character complex password displayed only on its physical screen. This must be typed into the Web UI alongside the Master PIN to unlock the vault.

Hardware UI (TFT Screen)
Camouflage Mode (Locked): Displays a fake "System Monitor" clock and disguises the 2FA session password.

Screensaver (Idle): After 10 seconds of inactivity, hides credential data and displays a large digital clock with a wake-up trap (pressing any button wakes the screen without executing an action).

Active Mode (Unlocked): Displays the current credential label, username, and live-updating 6-digit TOTP codes.

Credential Injection (HID)
Dual-Injection: Pressing the bottom button injects keystrokes via USB-C and Bluetooth simultaneously.

Sequential Typing: If a credential has a TOTP secret, the first button press types the password. The UI updates to prompt for 2FA, and the second button press types the live 6-digit TOTP code.

Web Interface (JavaScript/HTML)
Embedded as a compressed string in the C++ firmware.

Features Dark/Light theme toggling, live vault statistics (Total, Favs, Weak passwords), password strength meter, and advanced password generator (Length, Numbers, Symbols).

Smart Sorting: Automatically groups Favorites (⭐) at the top, followed by remaining entries alphabetically.

📂 File Structure (Internal LittleFS)
  
/vault.bin: The primary encrypted vault database.

/decoy.bin: The secondary (dummy) encrypted vault database.

/vault.tmp: Temporary upload file during backup restoration.

/import.csv: Temporary storage during mobile CSV imports (deleted immediately after processing).
