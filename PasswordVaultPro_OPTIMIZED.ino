/*
  ============================================================================
   AMMAR PASSWORDS  v10.1 ULTIMATE  -  LilyGO T-Display-S3
   (Themes, Stats, Decoy Vault, Favs, Adv Gen, Fast Scroll, UI Overhaul)
  ============================================================================
*/

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <vector>
#include <algorithm>
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "esp_system.h"

// Hardware specific
#include <TFT_eSPI.h>
#include <SPI.h>

// HID Keyboards
#define KeyReport BleKeyReport
#include <BleKeyboard.h>
#undef KeyReport
#include "esp_gap_ble_api.h"
#include "USB.h"
#include "USBHIDKeyboard.h"

// KDF constants are intentionally defined before any functions. Some Arduino
// IDE/ESP32-S3 preprocessor combinations report a false "not declared in this
// scope" error when these are typed globals in an .ino sketch.
#ifndef PBKDF2_ITERS
#define PBKDF2_ITERS 120000
#endif
#ifndef PBKDF2_LEGACY_ITERS
#define PBKDF2_LEGACY_ITERS 50000
#endif

// ============================ CONFIG (edit me) ==============================
static const char* AP_SSID      = "Vault-S3";
// WPA2 AP password must be 8+ characters. Change this before flashing.
static const char* AP_PASS      = "change-me-32chars";

static const char* BLE_NAME     = "MyDevice";
static const bool  BLE_REQUIRE_PASSKEY = true;
static const uint32_t BLE_PASSKEY      = 123456;

static const uint32_t LOCK_MS   = 5UL * 60UL * 1000UL;
static const uint32_t SAVER_MS  = 10UL * 1000UL;

static const int  PBKDF2_ITERS  = 120000;
static const int  DELAY_THRESHOLD = 3;     
static const bool WIPE_ENABLED    = false; 
static const int  WIPE_THRESHOLD  = 10;    

static const bool BLE_DEFAULT_ON  = true;
static const bool AP_DEFAULT_HIDDEN = false;
static const uint32_t AP_TIMEOUT_MIN = 0;

#define PIN_POWER_ON 15
#define TFT_BL 38
#define BTN_NAV 0
#define BTN_TYPE 14

// ===========================================================================

static const char* VAULT_PATH = "/vault.bin";
static const char* DECOY_PATH = "/decoy.bin";
static const char* BAK_PATH   = "/vault.bak";
static const char* TMP_PATH   = "/vault.tmp";
static const char* CSV_PATH   = "/import.csv";
static const int   MAX_ENTRIES = 200;
static const size_t MAX_LABEL_LEN = 64;
static const size_t MAX_USER_LEN  = 96;
static const size_t MAX_PASS_LEN  = 128;
static const size_t MAX_TOTP_LEN  = 96;
static const size_t MAX_PIN_LEN   = 64;

static const char US = (char)0x1F;
static const char RS = (char)0x1E;

WebServer server(80);
DNSServer  dns;
Preferences prefs;
IPAddress  apIP(192, 168, 4, 1);

BleKeyboard bleKeyboard(BLE_NAME, "Ammar", 100);
USBHIDKeyboard usbKeyboard;
TFT_eSPI tft = TFT_eSPI();

struct Entry {
  uint16_t id;
  String   label, user, pass, totp;
  bool     enter;
  uint8_t  spd;
  bool     fav;
};

std::vector<Entry> g_entries;
uint16_t g_nextId   = 1;
bool     g_unlocked = false;
bool     g_isDecoy  = false;
bool     g_needsKdfMigration = false;
uint8_t  g_key[32];
uint8_t  g_salt[16];
String   g_session  = "";
uint32_t g_lastSeen = 0;
String   g_bootPass  = "";

// Hardware Button State
int      g_selectedIndex = 0;
bool     btnNavLast = HIGH;
uint32_t btnNavPressTime = 0;
uint32_t lastFastScroll = 0;
uint32_t lastBtnType = 0;
bool     g_typeTotpNext = false;

bool     g_bleEnabled = true;
bool     g_bleStarted = false;
bool     g_apHidden   = false;
int      g_failCount  = 0;
uint32_t g_lastWebMs  = 0;
bool     g_apOff      = false;

uint32_t g_timeBase = 0, g_timeAtMs = 0;
bool     g_timeSynced = false;
uint32_t nowEpoch() { return g_timeSynced ? g_timeBase + (millis()-g_timeAtMs)/1000UL : 0; }

File g_upFile;

int base32Decode(const String& in, uint8_t* out, int maxOut);

// =========================== Small utilities ===============================
void fillRandom(uint8_t* b, size_t n) {
  for (size_t i = 0; i < n;) { uint32_t r = esp_random();
    for (int k = 0; k < 4 && i < n; k++, i++) b[i] = (r >> (8*k)) & 0xFF; }
}
String toHex(const uint8_t* b, size_t n) {
  static const char* h = "0123456789abcdef"; String s; s.reserve(n*2);
  for (size_t i = 0; i < n; i++) { s += h[b[i]>>4]; s += h[b[i]&0xF]; } return s;
}
String jsonEsc(const String& in) {
  String o; o.reserve(in.length()+8);
  for (size_t i = 0; i < in.length(); i++) { char c = in[i];
    switch (c) { case '"': o+="\\\""; break; case '\\': o+="\\\\"; break;
      case '\n': o+="\\n"; break; case '\r': o+="\\r"; break;
      case '\t': o+="\\t"; break;
      default: if ((uint8_t)c < 0x20) { char x[8]; sprintf(x,"\\u%04x",c); o+=x; } else o+=c;
    } } return o;
}
String sanitize(String s) { s.replace(String(US),""); s.replace(String(RS),""); return s; }
String truncateField(String s, size_t maxLen) { return s.length() > maxLen ? s.substring(0, maxLen) : s; }
bool validPin(const String& pin) { return pin.length() >= 6 && pin.length() <= MAX_PIN_LEN; }
bool validTotpSecret(const String& secret) {
  if (secret.length() == 0) return true;
  if (secret.length() > MAX_TOTP_LEN) return false;
  uint8_t tmp[64];
  return base32Decode(secret, tmp, sizeof(tmp)) > 0;
}
void sendJson(int code, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("X-Content-Type-Options", "nosniff");
  server.sendHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'");
  server.send(code, "application/json", body);
}

// ============================ Sort Vault (Favs First) ======================
void sortVault() {
  std::sort(g_entries.begin(), g_entries.end(), [](const Entry& a, const Entry& b) {
    if (a.fav != b.fav) return a.fav > b.fav;
    // Fix: Use strcasecmp for standard C++ case-insensitive string comparison
    return strcasecmp(a.label.c_str(), b.label.c_str()) < 0;
  });
}

// ============================ Settings & Crypto ============================
void loadSettings() {
  prefs.begin("ammar", false);
  g_bleEnabled = prefs.getBool("ble", BLE_DEFAULT_ON);
  g_apHidden   = prefs.getBool("hidden", AP_DEFAULT_HIDDEN);
  g_failCount  = prefs.getInt("fail", 0);
  prefs.end();
}
void saveBool(const char* k, bool v) { prefs.begin("ammar", false); prefs.putBool(k, v); prefs.end(); }
void saveFail(int v) { g_failCount = v; prefs.begin("ammar", false); prefs.putInt("fail", v); prefs.end(); }

bool deriveKeyWithIterations(const String& pin, const uint8_t* salt, int iterations, uint8_t* out) {
  mbedtls_md_context_t c; mbedtls_md_init(&c);
  const mbedtls_md_info_t* i = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mbedtls_md_setup(&c, i, 1) != 0) { mbedtls_md_free(&c); return false; }
  int r = mbedtls_pkcs5_pbkdf2_hmac(&c, (const unsigned char*)pin.c_str(), pin.length(), salt, 16, iterations, 32, out);
  mbedtls_md_free(&c); return r == 0;
}
bool deriveKey(const String& pin, const uint8_t* salt, uint8_t* out) {
  return deriveKeyWithIterations(pin, salt, PBKDF2_ITERS, out);
}
bool hmacSha1(const uint8_t* k, size_t kl, const uint8_t* m, size_t ml, uint8_t* out) {
  const mbedtls_md_info_t* i = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  return mbedtls_md_hmac(i, k, kl, m, ml, out) == 0;
}

// ============================ Base32 + TOTP ================================
int base32Decode(const String& in, uint8_t* out, int maxOut) {
  int buf = 0, bits = 0, cnt = 0;
  for (size_t i = 0; i < in.length(); i++) { char c = in[i];
    if (c==' '||c=='='||c=='\t'||c=='\n'||c=='\r') continue; int v;
    if (c>='A'&&c<='Z') v=c-'A'; else if (c>='a'&&c<='z') v=c-'a';
    else if (c>='2'&&c<='7') v=c-'2'+26; else return -1;
    buf=(buf<<5)|v; bits+=5;
    if (bits>=8) { bits-=8; if (cnt>=maxOut) return -1; out[cnt++]=(buf>>bits)&0xFF; } }
  return cnt;
}
String totpCode(const String& secret, uint32_t epoch) {
  uint8_t key[64]; int kl = base32Decode(secret, key, sizeof(key));
  if (kl <= 0) return "------";
  uint64_t ctr = epoch/30ULL; uint8_t msg[8];
  for (int i=7;i>=0;i--){ msg[i]=ctr&0xFF; ctr>>=8; }
  uint8_t h[20]; if (!hmacSha1(key,kl,msg,8,h)) return "------";
  int off = h[19]&0x0F;
  uint32_t bin = ((h[off]&0x7F)<<24)|((h[off+1]&0xFF)<<16)|((h[off+2]&0xFF)<<8)|(h[off+3]&0xFF);
  char b[7]; sprintf(b,"%06lu",(unsigned long)(bin%1000000UL)); return String(b);
}

// ======================= Vault serialize / persist ========================
String serializeVault() {
  String s; s += String(g_nextId); s += RS;
  for (auto& e : g_entries) {
    s += String(e.id); s+=US; s+=e.label; s+=US; s+=e.user; s+=US; s+=e.pass; s+=US;
    s += e.totp; s+=US; s += (e.enter?"1":"0"); s+=US; s += String(e.spd); s+=US;
    s += (e.fav?"1":"0"); s+=RS;
  } return s;
}
void parseVault(const String& s) {
  g_entries.clear(); int start=0; bool first=true;
  while (start < (int)s.length()) {
    int rs = s.indexOf(RS,start); if (rs<0) rs=s.length();
    String rec = s.substring(start,rs); start=rs+1;
    if (rec.length()==0){ first=false; continue; }
    if (first){ g_nextId=(uint16_t)rec.toInt(); first=false; continue; }
    String f[8]; int fi=0,p=0;
    while (fi<8){ int us=rec.indexOf(US,p); if (us<0){ f[fi++]=rec.substring(p); break; }
      f[fi++]=rec.substring(p,us); p=us+1; }
    Entry e; e.id=(uint16_t)f[0].toInt(); e.label=f[1]; e.user=f[2]; e.pass=f[3];
    e.totp=f[4]; e.enter=(f[5]=="1"); e.spd=(uint8_t)f[6].toInt();
    e.fav=(f[7]=="1");
    g_entries.push_back(e);
  }
  sortVault();
}
bool saveVault() {
  sortVault();
  String plain = serializeVault(); size_t pl = plain.length();
  uint8_t iv[12]; fillRandom(iv,12); uint8_t tag[16];
  uint8_t* ct = (uint8_t*)malloc(pl?pl:1); if (!ct) return false;
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  bool ok = (mbedtls_gcm_setkey(&g,MBEDTLS_CIPHER_ID_AES,g_key,256)==0);
  if (ok) ok = (mbedtls_gcm_crypt_and_tag(&g,MBEDTLS_GCM_ENCRYPT,pl,iv,12,NULL,0,(const unsigned char*)plain.c_str(),ct,16,tag)==0);
  mbedtls_gcm_free(&g);
  if (!ok){ free(ct); return false; }

  File f = LittleFS.open(g_isDecoy ? DECOY_PATH : VAULT_PATH,"w");
  if (!f){ free(ct); return false; }

  f.write(g_salt,16); f.write(iv,12); f.write(tag,16); if (pl) f.write(ct,pl);
  f.close(); free(ct); return true;
}

int tryUnlockFile(const char* path, const String& pin) {
  File f = LittleFS.open(path,"r"); if (!f) return 1;
  size_t total = f.size(); if (total<44){ f.close(); return 2; }
  uint8_t salt[16],iv[12],tag[16];
  f.read(salt,16); f.read(iv,12); f.read(tag,16);
  size_t cl = total-44;
  uint8_t* ct=(uint8_t*)malloc(cl?cl:1); uint8_t* pt=(uint8_t*)malloc(cl?cl:1);
  if (!ct||!pt){ if(ct)free(ct); if(pt)free(pt); f.close(); return 2; }
  if (cl) f.read(ct,cl); f.close();
  uint8_t key[32]; if (!deriveKey(pin,salt,key)){ free(ct); free(pt); return 2; }
  mbedtls_gcm_context g; mbedtls_gcm_init(&g); int ret = -1;
  if (mbedtls_gcm_setkey(&g,MBEDTLS_CIPHER_ID_AES,key,256)==0)
    ret = mbedtls_gcm_auth_decrypt(&g,cl,iv,12,NULL,0,tag,16,ct,pt);
  mbedtls_gcm_free(&g);

  bool usedLegacyKdf = false;
  if (ret != 0 && PBKDF2_LEGACY_ITERS != PBKDF2_ITERS) {
    memset(key,0,32);
    if (cl) memset(pt,0,cl);
    if (!deriveKeyWithIterations(pin,salt,PBKDF2_LEGACY_ITERS,key)){ free(ct); free(pt); return 2; }
    mbedtls_gcm_init(&g); ret = -1;
    if (mbedtls_gcm_setkey(&g,MBEDTLS_CIPHER_ID_AES,key,256)==0)
      ret = mbedtls_gcm_auth_decrypt(&g,cl,iv,12,NULL,0,tag,16,ct,pt);
    mbedtls_gcm_free(&g);
    usedLegacyKdf = (ret == 0);
  }

  free(ct); ct=nullptr;
  if (ret != 0) { memset(key,0,32); if(cl) memset(pt,0,cl); free(pt); return 1; }

  String plain; plain.reserve(cl+1);
  if (!plain.concat((const char*)pt, cl)) { memset(key,0,32); if(cl) memset(pt,0,cl); free(pt); return 2; }
  if (cl) memset(pt,0,cl); free(pt); pt=nullptr;

  parseVault(plain); plain = String();
  if (usedLegacyKdf) {
    // Migrate the in-memory key to the stronger iteration count; the caller
    // rewrites the vault once unlock completes so the next boot uses 120k.
    if (!deriveKey(pin,salt,key)) { memset(key,0,32); return 2; }
    g_needsKdfMigration = true;
  }
  memcpy(g_key,key,32); memcpy(g_salt,salt,16); memset(key,0,32);
  return 0;
}

int unlockVault(const String& pin) {
  std::vector<Entry>().swap(g_entries);
  g_needsKdfMigration = false;

  int res = tryUnlockFile(VAULT_PATH, pin);
  if (res == 0) {
      g_isDecoy = false; g_unlocked = true;
      g_selectedIndex = 0; g_typeTotpNext = false;
      if (g_needsKdfMigration) { saveVault(); g_needsKdfMigration = false; }
      return 0;
  }

  if (res == 1 && LittleFS.exists(DECOY_PATH)) {
      res = tryUnlockFile(DECOY_PATH, pin);
      if (res == 0) {
          g_isDecoy = true; g_unlocked = true;
          g_selectedIndex = 0; g_typeTotpNext = false;
          if (g_needsKdfMigration) { saveVault(); g_needsKdfMigration = false; }
          return 0;
      }
  }
  return res;
}

bool createVault(const String& pin, bool asDecoy = false) {
  fillRandom(g_salt,16); if (!deriveKey(pin,g_salt,g_key)) return false;
  g_entries.clear(); g_nextId=1; g_unlocked=true; g_isDecoy = asDecoy; g_needsKdfMigration = false;
  return saveVault();
}

void lockVault() {
  g_unlocked=false; g_session=""; memset(g_key,0,32); g_isDecoy = false; g_needsKdfMigration = false;
  for (auto& e:g_entries){ e.pass=""; e.totp=""; e.user=""; e.label=""; }
  std::vector<Entry>().swap(g_entries);
}

void wipeVault() { LittleFS.remove(VAULT_PATH); LittleFS.remove(DECOY_PATH); LittleFS.remove(BAK_PATH); lockVault(); saveFail(0); }
bool vaultExists() { return LittleFS.exists(VAULT_PATH); }
Entry* findEntry(uint16_t id) { for (auto& e:g_entries) if (e.id==id) return &e; return nullptr; }

// ============================ Auth / session ===============================
String cookieToken() {
  if (!server.hasHeader("Cookie")) return "";
  String c = server.header("Cookie"); int i = c.indexOf("sid="); if (i<0) return "";
  i+=4; int j=c.indexOf(';',i); if (j<0) j=c.length(); return c.substring(i,j);
}
bool authed() {
  if (!g_unlocked || g_session.length()==0) return false;
  if (cookieToken()!=g_session) return false;
  if (millis()-g_lastSeen > LOCK_MS) { lockVault(); return false; }
  g_lastSeen = millis(); g_lastWebMs = millis(); return true;
}
void newSession() { uint8_t t[16]; fillRandom(t,16); g_session=toHex(t,16); g_lastSeen=millis(); }

// ============================ Hardware Session Generator ===================
// Fix: Added back the C++ generator required for the boot screen 2FA
String genPassword(int len) {
  const char* lo="abcdefghijkmnpqrstuvwxyz"; const char* up="ABCDEFGHJKLMNPQRSTUVWXYZ";
  const char* di="23456789"; const char* sy="!@#$%^&*()-_=+[]{}?";
  String pools[4]={lo,up,di,sy}; if (len<8) len=8; if (len>64) len=64; String out="";
  for (int c=0;c<4;c++){ const String& p=pools[c]; out+=p[esp_random()%p.length()]; }
  String all=String(lo)+up+di+sy;
  for (int i=4;i<len;i++) out+=all[esp_random()%all.length()];
  for (int i=out.length()-1;i>0;i--){ int j=esp_random()%(i+1); char t=out[i]; out[i]=out[j]; out[j]=t; }
  return out;
}

// ============================ Advanced Auto-Type ===========================
void configureBleSecurity() {
  uint32_t passkey = BLE_PASSKEY;
  esp_ble_auth_req_t auth = ESP_LE_AUTH_REQ_SC_MITM_BOND;
  esp_ble_io_cap_t  iocap = ESP_IO_CAP_OUT;
  uint8_t ksize = 16;
  uint8_t ikey  = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint8_t rkey  = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &ksize, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &ikey, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rkey, sizeof(uint8_t));
}
void startBleIfEnabled() {
  if (g_bleEnabled && !g_bleStarted) { bleKeyboard.begin(); if (BLE_REQUIRE_PASSKEY) configureBleSecurity(); g_bleStarted = true; }
}

void typeText(const String& t, uint8_t per) {
  uint8_t d = per ? per : 8;
  for (size_t i = 0; i < t.length(); i++) {
    if (bleKeyboard.isConnected()) bleKeyboard.print(t[i]);
    usbKeyboard.print(t[i]); delay(d);
  }
}

bool doType(Entry* e, const String& mode) {
  bool bleReady = bleKeyboard.isConnected();

  if (mode=="user") typeText(e->user,e->spd);
  else if (mode=="pass") typeText(e->pass,e->spd);
  else if (mode=="totp") { if (!g_timeSynced) return false; typeText(totpCode(e->totp,nowEpoch()),e->spd); }
  else if (mode=="both"||mode=="bothenter") {
    typeText(e->user,e->spd); delay(40);
    if(bleReady) bleKeyboard.write(KEY_TAB); usbKeyboard.write(KEY_TAB);
    delay(40); typeText(e->pass,e->spd);
  } else return false;

  if (mode=="bothenter" || (e->enter && mode!="user")) {
    delay(40); if(bleReady) bleKeyboard.write(KEY_RETURN); usbKeyboard.write(KEY_RETURN);
  }
  return true;
}

// =============================== WEB UI ======================================
const char STYLE[] PROGMEM = R"css(
<style>
:root{--bg:#f8fafc;--card:#ffffff;--text:#1e293b;--text-sec:#64748b;--border:#e2e8f0;--accent:#2563eb;--accent-hover:#1d4ed8;--warn:#ef4444;--ok:#10b981;--fav:#fbbf24;}
[data-theme="dark"]{--bg:#0f1722;--card:#16212f;--text:#e7eef7;--text-sec:#8aa0b8;--border:#243245;--accent:#3b82f6;--accent-hover:#60a5fa;}
*{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);transition:background 0.3s}
.wrap{max-width:600px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0 0 4px;font-weight:700} .sub{color:var(--text-sec);font-size:13px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 2px 4px rgb(0 0 0 / 0.05)}
.dash{display:flex;gap:10px;margin-bottom:16px}
.stat{flex:1;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center;box-shadow:0 2px 4px rgb(0 0 0 / 0.05)}
.stat-val{font-size:20px;font-weight:bold;color:var(--accent)} .stat-lbl{font-size:11px;color:var(--text-sec);text-transform:uppercase;letter-spacing:1px}
.bar{display:flex;gap:8px;flex-wrap:wrap;font-size:12px;margin-bottom:12px;align-items:center}
.pill{background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:4px 10px;font-weight:500}
.ok-t{color:var(--ok)} .bad-t{color:var(--warn)}
input,select{width:100%;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:14px;margin:6px 0;transition:border 0.2s}
input:focus{outline:none;border-color:var(--accent)}
label{font-size:12px;color:var(--text-sec);font-weight:500}
button{cursor:pointer;border:0;border-radius:8px;padding:10px 14px;font-size:14px;font-weight:600;background:var(--accent);color:#fff;transition:0.2s}
button:hover{background:var(--accent-hover)}
button.sec{background:var(--bg);color:var(--text);border:1px solid var(--border)} button.sec:hover{background:var(--border)}
button.warn{background:var(--warn);color:#fff} button.sm{padding:6px 10px;font-size:12px} button.icon{padding:8px;display:flex;align-items:center;justify-content:center}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:12px 0;border-bottom:1px solid var(--border)} .row:last-child{border-bottom:0}
.elabel{font-weight:600;font-size:15px;display:flex;align-items:center;gap:6px} .euser{font-size:12px;color:var(--text-sec);margin-top:2px}
.btns{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.full{width:100%} .msg{font-size:13px;min-height:18px;color:var(--warn);margin:6px 0}
.reveal{font-family:monospace;background:var(--bg);border:1px dashed var(--border);border-radius:6px;padding:8px;margin-top:8px;word-break:break-all;display:none;font-size:13px}
.grid2{display:flex;gap:8px;align-items:end} .grid2>div{flex:1}
details summary{cursor:pointer;color:var(--text-sec);font-size:13px;margin:8px 0;font-weight:500;user-select:none}
.str-meter{height:4px;border-radius:2px;background:var(--border);margin-top:2px;overflow:hidden}
.str-fill{height:100%;width:0%;transition:0.3s}
.folder{margin-bottom:16px;} .folder-title{font-size:11px;text-transform:uppercase;color:var(--text-sec);letter-spacing:1px;margin:0 0 8px 4px}
.fav-btn{color:var(--border);background:none;border:none;padding:0;font-size:18px;cursor:pointer} .fav-btn.active{color:var(--fav)}
.head-flex{display:flex;justify-content:space-between;align-items:start}
.theme-btn{background:none;border:1px solid var(--border);color:var(--text);font-size:18px;padding:4px 8px}
.toolbar{display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:10px}
.pager{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:10px 0}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
</style>)css";

void sendHtml(const String& body) {
  String p = FPSTR(STYLE);
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("X-Content-Type-Options", "nosniff");
  server.sendHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'");
  p += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p += "<div class='wrap'>" + body + "</div>";
  server.send(200, "text/html", p);
}

void pageSetup() {
  String b =
    "<div class='head-flex'><div><h1>Vault Initialization</h1><div class='sub'>Create your secure space</div></div></div>"
    "<div class='card'><label>Create a Master PIN</label>"
    "<input id='p1' type='password' placeholder='Master PIN'>"
    "<input id='p2' type='password' placeholder='Confirm PIN'>"
    "<div class='msg' id='m'></div>"
    "<button class='full' onclick='setup()'>Initialize System</button></div>"
    "<script>"
    "function setup(){var a=p1.value,b=p2.value;"
    "if(a.length<6||a.length>64){m.innerText='PIN must be 6-64 characters';return;}"
    "if(a!=b){m.innerText='PINs do not match';return;}"
    "fetch('/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
    "body:'pin='+encodeURIComponent(a)}).then(r=>r.json()).then(j=>{if(j.ok)location.href='/';else m.innerText=j.error||'Failed';});}"
    "</script>";
  sendHtml(b);
}

void pageLock() {
  String b =
    "<h1>Access Required</h1><div class='sub'>Encrypted Storage System</div>"
    "<div class='card'>"
    "<label>Master PIN</label>"
    "<input id='pin' type='password' placeholder='Enter PIN' autofocus>"
    "<label>Session Password (From Device Screen)</label>"
    "<input id='bpin' type='text' placeholder='Generated Password' autocomplete='off'>"
    "<div class='msg' id='m'></div>"
    "<button class='full' onclick='go()'>Authenticate</button></div>"
    "<script>"
    "document.addEventListener('keydown',e=>{if(e.key=='Enter')go();});"
    "function go(){fetch('/unlock',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
    "body:'pin='+encodeURIComponent(pin.value)+'&bootpin='+encodeURIComponent(bpin.value)}).then(r=>r.json()).then(j=>{"
    "if(j.ok){location.href='/';}else{m.innerText=j.msg||'Access Denied';pin.value='';bpin.value='';}});}"
    "</script>";
  sendHtml(b);
}

extern const char MAIN_JS[];
void pageMain() {
  String b =
    "<div class='head-flex'><div><h1>Credential Vault</h1><div class='sub' id='vtype'>Secure Storage</div></div>"
    "<button class='theme-btn' onclick='toggleTheme()'>🌓</button></div>"

    // Security Dashboard
    "<div class='dash'>"
      "<div class='stat'><div class='stat-val' id='s-tot'>0</div><div class='stat-lbl'>Total</div></div>"
      "<div class='stat'><div class='stat-val' id='s-fav'>0</div><div class='stat-lbl'>Favs</div></div>"
      "<div class='stat'><div class='stat-val bad-t' id='s-weak'>0</div><div class='stat-lbl'>Weak</div></div>"
    "</div>"

    "<div class='bar'>"
      "<span class='pill ok-t'>Authenticated</span>"
      "<span class='pill' id='ble'>BLE: ...</span>"
      "<a class='tog pill' href='#' onclick='lock();return false' style='color:var(--warn)'>Lock Vault</a>"
    "</div>"
    
    "<div class='toolbar'>"
      "<div><label class='sr-only' for='q'>Search credentials</label><input id='q' placeholder='Search domains, users, tags...' oninput='page=1;render()'></div>"
      "<div><label for='sort'>Sort</label><select id='sort' onchange='page=1;render()'><option value='smart'>Smart</option><option value='az'>A-Z</option><option value='za'>Z-A</option><option value='weak'>Weak first</option></select></div>"
    "</div>"
    "<div id='list'></div>"
    "<div class='pager'><button class='sec sm' onclick='prevPage()'>Previous</button><span class='pill' id='pageinfo'>Page 1</span><button class='sec sm' onclick='nextPage()'>Next</button></div>"
    
    // Add/Edit Form
    "<div class='card' style='margin-top:20px'><div class='elabel' id='formtitle'>Create Entry</div>"
      "<input id='nl' placeholder='Platform / Website (e.g. Github)'>"
      "<input id='nu' placeholder='Username or Email'>"
      "<div class='grid2'>"
        "<div style='flex:3'><input id='np' placeholder='Password' oninput='checkStr()'>"
          "<div class='str-meter'><div class='str-fill' id='meter'></div></div>"
        "</div>"
        "<div style='flex:1'><button class='sec full' onclick='openGen()'>⚙️ Gen</button></div>"
      "</div>"

      // Advanced Generator Modal (Hidden by default)
      "<div id='genUI' style='display:none;background:var(--bg);padding:10px;border-radius:6px;margin:8px 0;border:1px solid var(--border)'>"
        "<div class='row' style='padding:4px 0'><span>Length (<span id='g-len-val'>16</span>)</span><input type='range' id='g-len' min='8' max='32' value='16' oninput='document.getElementById(\"g-len-val\").innerText=this.value'></div>"
        "<div style='display:flex;gap:10px;margin-top:8px'><label><input type='checkbox' id='g-num' checked> 0-9</label><label><input type='checkbox' id='g-sym' checked> !@#</label></div>"
        "<button class='full sm' style='margin-top:10px' onclick='doGen()'>Apply Generated Password</button>"
      "</div>"

      "<input id='nt' placeholder='TOTP Secret (Base32, Optional)'>"
      "<div class='grid2'>"
        "<div><label>Auto-Enter</label><select id='ne'><option value='0'>No</option><option value='1'>Yes</option></select></div>"
        "<div><label>Type Speed</label><input id='nd' type='number' value='12'></div>"
      "</div>"
      "<label style='display:flex;align-items:center;gap:6px;margin-top:10px;cursor:pointer'><input type='checkbox' id='nf' style='width:auto'> Mark as Favorite ⭐</label>"
      "<div class='msg' id='am'></div>"
      "<button class='full' onclick='save()'>Save Credential</button>"
      "<button class='sec full' id='cancel' style='display:none;margin-top:6px' onclick='clearForm()'>Cancel</button>"
    "</div>"

    // Settings
    "<details><summary>System Settings & Maintenance</summary><div class='card'>"
      "<div class='row'><div>Bluetooth Interface</div><div class='btns'><button class='sm sec' onclick='setble(1)'>Enable</button><button class='sm warn' onclick='setble(0)'>Disable</button></div></div>"
      "<div class='row'><div>Create Decoy Vault</div><div class='btns'><button class='sm sec' onclick='setupDecoy()'>Initialize</button></div></div>"
      "<div class='row'><div>Encrypted Backup</div><div class='btns'><button class='sm sec' onclick='expt()'>Download</button></div></div>"
      "<div class='msg' id='sm'></div>"
    "</div></details>"

    "<script>" + String(MAIN_JS) + "</script>";
  sendHtml(b);
}

const char MAIN_JS[] PROGMEM = R"js(
var DATA=[]; var editId=0; var page=1; var pageSize=12; var filteredCount=0;
// Theme Init
if(localStorage.getItem('theme')==='dark') document.documentElement.setAttribute('data-theme','dark');
function toggleTheme() {
  var t = document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
}

function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

function checkStr() {
  var p=document.getElementById('np').value, m=document.getElementById('meter'), s=0;
  if(p.length>7)s++; if(p.match(/[A-Z]/))s++; if(p.match(/[0-9]/))s++; if(p.match(/[^a-zA-Z0-9]/))s++;
  var c=['#ef4444','#fbbf24','#fbbf24','#10b981','#10b981'][s];
  m.style.width=(s*25)+'%'; m.style.backgroundColor=p?c:'transparent';
}

function openGen() { var e=document.getElementById('genUI'); e.style.display=e.style.display=='none'?'block':'none'; }
function doGen() {
  var len=document.getElementById('g-len').value;
  var useNum=document.getElementById('g-num').checked;
  var useSym=document.getElementById('g-sym').checked;
  var lo="abcdefghijkmnpqrstuvwxyz", up="ABCDEFGHJKLMNPQRSTUVWXYZ", di="23456789", sy="!@#$%^&*()-_=+";
  var pool=lo+up+(useNum?di:"")+(useSym?sy:"");
  var res=""; for(var i=0;i<len;i++) res+=pool[Math.floor(Math.random()*pool.length)];
  document.getElementById('np').value=res; checkStr(); openGen();
}

function status(){fetch('/api/status').then(r=>r.json()).then(j=>{
  var b=document.getElementById('ble');b.innerText='BLE: '+(!j.bleon?'Off':(j.ble?'Conn':'Wait'));
  b.className='pill '+(j.ble?'ok-t':'bad-t');
  if(j.decoy) document.getElementById('vtype').innerText='Decoy Storage (Isolated)';
});}

function load(){fetch('/api/list').then(r=>r.json()).then(a=>{DATA=a;render();});}

function updateDash(arr) {
  document.getElementById('s-tot').innerText = arr.length;
  document.getElementById('s-fav').innerText = arr.filter(e=>e.fav).length;
  document.getElementById('s-weak').innerText = arr.filter(e=>e.weak).length;
}

function sortedItems(arr){
  var mode=document.getElementById('sort')?document.getElementById('sort').value:'smart';
  return arr.slice().sort((a,b)=>{
    if(mode==='weak' && a.weak!==b.weak) return a.weak?-1:1;
    if(mode==='za') return (b.label||'').localeCompare(a.label||'', undefined, {sensitivity:'base'});
    if(mode==='smart' && a.fav!==b.fav) return a.fav?-1:1;
    return (a.label||'').localeCompare(b.label||'', undefined, {sensitivity:'base'});
  });
}
function prevPage(){ if(page>1){page--;render();} }
function nextPage(){ if(page*pageSize<filteredCount){page++;render();} }

function render(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var arr=sortedItems(DATA.filter(e=>!q||(e.label+' '+e.user).toLowerCase().indexOf(q)>=0));
  updateDash(DATA); // Update dash based on total data

  if(!arr.length){document.getElementById('list').innerHTML="<div class='card' style='text-align:center'>No records found.</div>";return;}
  filteredCount=arr.length;
  var pages=Math.max(1,Math.ceil(filteredCount/pageSize)); if(page>pages) page=pages;
  var visible=arr.slice((page-1)*pageSize,page*pageSize);
  document.getElementById('pageinfo').innerText='Page '+page+' / '+pages+' · '+filteredCount+' shown';
  
  // Grouping: Favs first, then Alphabetical Folders
  var favs = visible.filter(e=>e.fav);
  var others = visible.filter(e=>!e.fav);
  
  var h='';
  if(favs.length) h += buildGroup('★ Favorites', favs);

  // Smart Folders for the rest (Group by first letter of label)
  var groups = {};
  others.forEach(e=>{ var l=(e.label.charAt(0)||'#').toUpperCase(); if(!groups[l]) groups[l]=[]; groups[l].push(e); });
  Object.keys(groups).sort().forEach(k => { h += buildGroup(k, groups[k]); });

  document.getElementById('list').innerHTML=h;
}

function buildGroup(title, items) {
  var h = "<div class='folder'><div class='folder-title'>"+esc(title)+"</div>";
  items.forEach(e=>{
    var strWarn = e.weak ? "<span title='Weak Password' style='color:var(--warn);font-size:10px'>⚠️</span> " : "";
    h+="<div class='card' style='margin-bottom:8px'><div class='row'><div><div class='elabel'>"+strWarn+esc(e.label)+"</div>"+
    "<div class='euser'>"+esc(e.user||'-')+(e.hasTotp?' &middot; 2FA':'')+"</div></div><div class='btns'>"+
    "<button class='icon sec' onclick=\"toggleFav("+e.id+")\">"+(e.fav?"⭐":"☆")+"</button>"+
    "<button class='sm' onclick=\"tp("+e.id+",'bothenter')\">Auto</button>"+
    "<button class='sm sec' onclick=\"tp("+e.id+",'pass')\">Pass</button>"+
    "<button class='sm sec' onclick=\"show("+e.id+")\">View</button>"+
    "<button class='sm sec' onclick=\"edit("+e.id+")\">Edit</button>"+
    "<button class='sm warn' onclick=\"delEntry("+e.id+")\">Delete</button>"+
    "</div></div><div class='reveal' id='r"+e.id+"'></div></div>";
  });
  return h + "</div>";
}

function tp(id,mode){fetch('/api/type',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id+'&mode='+mode}).then(r=>r.json()).then(j=>{if(!j.ok)alert(j.error||'Type failed');});}
function toggleFav(id) { fetch('/api/fav',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id}).then(()=>load()); }
function delEntry(id){if(confirm('Delete this credential?'))fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id}).then(()=>load());}

function show(id){var el=document.getElementById('r'+id);
  if(el.style.display=='block'){el.style.display='none';return;}
  fetch('/api/secret?id='+id).then(r=>r.json()).then(j=>{
    var code=j.totp?(' | 2FA: '+j.totp):'';
    el.innerHTML='USR: '+esc(j.user)+'<br>PWD: '+esc(j.pass)+code+
      "<br><button class='sm sec' style='margin-top:6px' onclick=\"copyPass("+id+")\">Copy Pass</button>";
    el.dataset.pass=j.pass||'';
    el.style.display='block';});}
function copyPass(id){var el=document.getElementById('r'+id);navigator.clipboard.writeText(el.dataset.pass||'');}

function edit(id){var e=DATA.find(x=>x.id==id);if(!e)return;
  fetch('/api/secret?id='+id).then(r=>r.json()).then(j=>{
    editId=id;document.getElementById('formtitle').innerText='Edit Credential';
    nl.value=e.label;nu.value=j.user;np.value=j.pass;nt.value='';
    nf.checked=e.fav; checkStr();
    document.getElementById('cancel').style.display='block';
    window.scrollTo({top:document.body.scrollHeight, behavior:'smooth'});});}

function clearForm(){editId=0;nl.value='';nu.value='';np.value='';nt.value='';nf.checked=false;
  document.getElementById('formtitle').innerText='Create Entry'; checkStr();
  document.getElementById('cancel').style.display='none';am.innerText='';}

function save(){var l=nl.value.trim();if(!l){am.innerText='Label required';return;}
  if(l.length>64||nu.value.length>96||np.value.length>128||nt.value.length>96){am.innerText='One or more fields exceeds the allowed length.';return;}
  var body=(editId?'id='+editId+'&':'')+'label='+encodeURIComponent(l)+'&user='+encodeURIComponent(nu.value)+
    '&pass='+encodeURIComponent(np.value)+'&totp='+encodeURIComponent(nt.value)+
    '&enter='+ne.value+'&spd='+nd.value+'&fav='+(nf.checked?'1':'0');
  fetch(editId?'/api/update':'/api/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(r=>r.json()).then(j=>{if(j.ok){clearForm();load();}else am.innerText=j.error;});}

function setupDecoy(){
  var p=prompt("Enter a new PIN for the Decoy Vault:");
  if(p&&p.length>=6&&p.length<=64){
    fetch('/api/setup_decoy',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'pin='+encodeURIComponent(p)})
    .then(r=>r.json()).then(j=>{if(j.ok){alert("Decoy Created. Lock vault and test the new PIN.");}else{alert("Failed");}});
  }else if(p){alert("PIN must be 6-64 characters");}
}

function setble(on){if(confirm('Restarts device. Continue?')){fetch('/api/setble?on='+on,{method:'POST'});}}
function expt(){window.location='/api/export';}
function lock(){fetch('/logout').then(()=>location.href='/');}

status();load();setInterval(status,5000);
fetch('/api/time',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'t='+Math.floor(Date.now()/1000)});
)js";

// ============================ HTTP handlers ================================
void handleRoot() {
  g_lastWebMs = millis();
  if (!vaultExists()) { pageSetup(); return; }
  if (!authed())      { pageLock();  return; }
  pageMain();
}
void handleSetup() {
  if (vaultExists()) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Vault exists\"}"); return; }
  String pin = server.arg("pin");
  if (!validPin(pin)) { server.send(200,"application/json","{\"ok\":false,\"error\":\"PIN must be 6-64 characters\"}"); return; }
  if (createVault(pin, false)) { saveFail(0); newSession();
    server.sendHeader("Set-Cookie","sid="+g_session+"; Path=/; HttpOnly; SameSite=Strict");
    server.send(200,"application/json","{\"ok\":true}");
  } else server.send(200,"application/json","{\"ok\":false,\"error\":\"Create failed\"}");
}
void apiSetupDecoy() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  String pin = server.arg("pin");
  if (!validPin(pin)) { server.send(200,"application/json","{\"ok\":false,\"error\":\"PIN must be 6-64 characters\"}"); return; }
  // Save current main vault state to memory
  std::vector<Entry> backup = g_entries;
  uint16_t b_id = g_nextId;

  if (createVault(pin, true)) {
    // Restore state back to main vault
    g_entries = backup; g_nextId = b_id; g_isDecoy = false;
    server.send(200,"application/json","{\"ok\":true}");
  } else {
    g_entries = backup; g_nextId = b_id; g_isDecoy = false;
    server.send(200,"application/json","{\"ok\":false,\"error\":\"Failed\"}");
  }
}

void handleUnlock() {
  g_lastWebMs = millis();
  if (g_failCount >= DELAY_THRESHOLD) {
    uint32_t d = (uint32_t)(g_failCount - DELAY_THRESHOLD + 1) * 2000UL;
    if (d > 15000UL) d = 15000UL; delay(d);
  }

  String bootpin = server.arg("bootpin");
  String pin = server.arg("pin");

  if (bootpin != g_bootPass) { server.send(200,"application/json","{\"ok\":false,\"msg\":\"Invalid Session Password\"}"); return; }

  int res = unlockVault(pin);
  if (res == 0) {
    saveFail(0); newSession();
    server.sendHeader("Set-Cookie","sid="+g_session+"; Path=/; HttpOnly; SameSite=Strict");
    server.send(200,"application/json","{\"ok\":true}");
  } else if (res == 2) {
    server.send(200,"application/json","{\"ok\":false,\"msg\":\"Low memory - restarting...\"}"); delay(300); ESP.restart();
  } else {
    saveFail(g_failCount + 1);
    if (WIPE_ENABLED && g_failCount >= WIPE_THRESHOLD) {
      wipeVault(); server.send(200,"application/json","{\"ok\":false,\"msg\":\"Too many attempts - vault wiped\"}");
    } else {
      server.send(200,"application/json","{\"ok\":false,\"msg\":\"Wrong PIN\"}");
    }
  }
}
void handleLogout() { lockVault(); server.send(200,"application/json","{\"ok\":true}"); }

void apiStatus() {
  String j = "{";
  j += "\"ble\":";    j += (bleKeyboard.isConnected()?"true":"false");
  j += ",\"bleon\":"; j += (g_bleEnabled?"true":"false");
  j += ",\"decoy\":"; j += (g_isDecoy?"true":"false");
  j += "}";
  server.send(200,"application/json",j);
}

// Very basic password strength check for UI transmission
bool isWeak(const String& p) {
    int s=0;
    if(p.length()>7)s++;
    for(size_t i=0;i<p.length();i++){
        if(p[i]>='A'&&p[i]<='Z'){s++;break;}
    }
    for(size_t i=0;i<p.length();i++){
        if(p[i]>='0'&&p[i]<='9'){s++;break;}
    }
    return s < 2;
}

void apiList() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  String j="["; bool first=true;
  for (auto& e:g_entries) { if (!first) j+=","; first=false;
    j += "{\"id\":"+String(e.id);
    j += ",\"label\":\""+jsonEsc(e.label)+"\"";
    j += ",\"user\":\""+jsonEsc(e.user)+"\"";
    j += ",\"fav\":"+String(e.fav?"true":"false");
    j += ",\"weak\":"+String(isWeak(e.pass)?"true":"false");
    j += ",\"hasTotp\":"+String(e.totp.length()?"true":"false")+"}";
  }
  j += "]"; server.send(200,"application/json",j);
}

void apiSecret() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  Entry* e = findEntry((uint16_t)server.arg("id").toInt());
  if (!e) { server.send(404,"application/json","{\"error\":\"not found\"}"); return; }
  String totp=""; if (e->totp.length() && g_timeSynced) totp=totpCode(e->totp,nowEpoch());
  String j="{\"user\":\""+jsonEsc(e->user)+"\",\"pass\":\""+jsonEsc(e->pass)+"\",\"totp\":\""+jsonEsc(totp)+"\"}";
  server.send(200,"application/json",j);
}

void fillFromArgs(Entry& e) {
  e.label = truncateField(sanitize(server.arg("label")), MAX_LABEL_LEN);
  e.user  = truncateField(sanitize(server.arg("user")), MAX_USER_LEN);
  e.pass  = truncateField(sanitize(server.arg("pass")), MAX_PASS_LEN);
  e.totp  = truncateField(sanitize(server.arg("totp")), MAX_TOTP_LEN); e.totp.replace(" ","");
  e.enter = (server.arg("enter")=="1");
  e.fav   = (server.arg("fav")=="1");
  int spd = server.arg("spd").toInt(); if (spd<0) spd=0;
  if (spd>200) spd=200; e.spd=(uint8_t)spd;
}

void apiAdd() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  if ((int)g_entries.size() >= MAX_ENTRIES) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Vault is full\"}"); return; }
  
  String nLabel = truncateField(sanitize(server.arg("label")), MAX_LABEL_LEN);
  String nUser = truncateField(sanitize(server.arg("user")), MAX_USER_LEN);
  if (nLabel.length()==0) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Label required\"}"); return; }
  String nTotp = truncateField(sanitize(server.arg("totp")), MAX_TOTP_LEN); nTotp.replace(" ","");
  if (!validTotpSecret(nTotp)) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Invalid TOTP secret\"}"); return; }
  
  // Duplicate Check
  for(auto& existing : g_entries) {
      if(existing.label.equalsIgnoreCase(nLabel) && existing.user.equalsIgnoreCase(nUser)) {
          server.send(200,"application/json","{\"ok\":false,\"error\":\"Duplicate Warning: An entry with this Label & User already exists.\"}"); return;
      }
  }

  Entry e; e.id=g_nextId++; fillFromArgs(e); g_entries.push_back(e);
  if (saveVault()) server.send(200,"application/json","{\"ok\":true}");
  else { g_entries.pop_back(); g_nextId--; server.send(200,"application/json","{\"ok\":false,\"error\":\"Save failed\"}"); }
}

void apiUpdate() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  Entry* e = findEntry((uint16_t)server.arg("id").toInt());
  if (!e) { server.send(404,"application/json","{\"ok\":false,\"error\":\"not found\"}"); return; }
  if (truncateField(sanitize(server.arg("label")), MAX_LABEL_LEN).length()==0) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Label required\"}"); return; }
  String nTotp = truncateField(sanitize(server.arg("totp")), MAX_TOTP_LEN); nTotp.replace(" ","");
  if (!validTotpSecret(nTotp)) { server.send(200,"application/json","{\"ok\":false,\"error\":\"Invalid TOTP secret\"}"); return; }
  
  uint16_t id = e->id; Entry tmp; tmp.id=id; fillFromArgs(tmp);
  *e = tmp;
  if (saveVault()) server.send(200,"application/json","{\"ok\":true}");
  else server.send(200,"application/json","{\"ok\":false,\"error\":\"Save failed\"}");
}

void apiDelete() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  uint16_t id=(uint16_t)server.arg("id").toInt();
  for (size_t i=0;i<g_entries.size();i++) if (g_entries[i].id==id){ g_entries.erase(g_entries.begin()+i); break; }
  saveVault(); server.send(200,"application/json","{\"ok\":true}");
}

void apiFav() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  Entry* e = findEntry((uint16_t)server.arg("id").toInt());
  if (e) { e->fav = !e->fav; saveVault(); server.send(200,"application/json","{\"ok\":true}"); }
  else { server.send(404,"application/json","{\"ok\":false,\"error\":\"not found\"}"); }
}

void apiType() {
  if (!authed()) { server.send(401,"application/json","{\"error\":\"locked\"}"); return; }
  Entry* e = findEntry((uint16_t)server.arg("id").toInt()); String mode=server.arg("mode");
  if (!e) { server.send(404,"application/json","{\"ok\":false,\"error\":\"not found\"}"); return; }
  bool ok = doType(e,mode);
  server.send(200,"application/json", ok?"{\"ok\":true}":"{\"ok\":false,\"error\":\"Type failed\"}");
}

void apiTime() {
  uint32_t t = (uint32_t)strtoul(server.arg("t").c_str(),NULL,10);
  if (t > 1600000000UL) { g_timeBase=t; g_timeAtMs=millis(); g_timeSynced=true; }
  server.send(200,"application/json","{\"ok\":true}");
}

void apiExport() {
  if (!authed()) { server.send(401,"text/plain","locked"); return; }
  File f = LittleFS.open(g_isDecoy ? DECOY_PATH : VAULT_PATH,"r");
  if (!f) { server.send(404,"text/plain","no vault"); return; }
  server.sendHeader("Content-Disposition","attachment; filename=vault-backup.bin");
  server.streamFile(f,"application/octet-stream"); f.close();
}

void apiSetBle() { bool on = (server.arg("on")=="1"); saveBool("ble",on); server.send(200,"application/json","{\"ok\":true}"); delay(300); ESP.restart(); }
void handleNotFound() { server.sendHeader("Location", String("http://")+apIP.toString()+"/", true); server.send(302,"text/plain",""); }

// ============================ Display Core =================================
void updateScreenUI(bool forceUpdate = false) {
  static uint32_t lastDraw = 0;

  if (millis() - lastDraw > 1000 || forceUpdate) {
    lastDraw = millis();
    tft.fillScreen(TFT_BLACK);

    // Status Bar
    tft.fillRect(0, 0, 320, 20, TFT_DARKGREY);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.drawString(WiFi.softAPIP().toString(), 5, 2, 2);

    if (!g_unlocked) {
        // --- LOCKED: Show Fake Clock & Boot Password ---
        tft.drawString("STANDBY", 260, 2, 2);

        uint32_t secs = millis() / 1000;
        char timeStr[9];
        sprintf(timeStr, "%02d:%02d:%02d", (secs / 3600) % 24, (secs / 60) % 60, secs % 60);

        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.drawCentreString(timeStr, 160, 50, 7);

        tft.setTextColor(TFT_YELLOW, TFT_BLACK);
        tft.drawCentreString("SESSION PASS:", 160, 110, 2);
        tft.setTextColor(TFT_CYAN, TFT_BLACK);
        tft.drawCentreString(g_bootPass, 160, 130, 4);

    } else if (millis() - g_lastSeen > SAVER_MS) {
        // --- SCREENSAVER ---
        tft.drawString("IDLE", 280, 2, 2);
        tft.drawRoundRect(10, 25, 300, 135, 10, TFT_BLUE);
        tft.drawRoundRect(12, 27, 296, 131, 8, TFT_DARKCYAN);

        uint32_t secs = millis() / 1000;
        char timeStr[9]; sprintf(timeStr, "%02d:%02d:%02d", (secs / 3600) % 24, (secs / 60) % 60, secs % 60);

        tft.setTextColor(TFT_CYAN, TFT_BLACK);
        tft.drawCentreString(timeStr, 160, 55, 7);
        tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
        tft.drawCentreString(g_isDecoy ? "Decoy Vault" : "Vault is Unlocked", 160, 115, 2);
        tft.drawCentreString("Press any button to wake", 160, 135, 2);

    } else {
        // --- UNLOCKED & ACTIVE ---
        String connState = bleKeyboard.isConnected() ? "(BLE & USB)" : "(USB)";
        tft.drawString("ACTIVE " + connState, 190, 2, 2);

        if (g_entries.empty()) {
            tft.setTextColor(TFT_YELLOW, TFT_BLACK);
            tft.drawCentreString("Vault is Empty", 160, 80, 4);
        } else {
            if (g_selectedIndex >= g_entries.size()) g_selectedIndex = 0;
            Entry& e = g_entries[g_selectedIndex];

            // Draw Label with Star if Favorite
            tft.setTextColor(e.fav ? TFT_YELLOW : TFT_CYAN, TFT_BLACK);
            tft.drawCentreString((e.fav ? "* " : "") + e.label + (e.fav ? " *" : ""), 160, 35, 4);

            // Draw Username
            tft.setTextColor(TFT_WHITE, TFT_BLACK);
            tft.drawCentreString(e.user, 160, 65, 2);

            // Draw Live TOTP if it exists
            if (e.totp.length() > 0) {
                tft.setTextColor(TFT_ORANGE, TFT_BLACK);
                if (g_timeSynced) tft.drawCentreString("2FA: " + totpCode(e.totp, nowEpoch()), 160, 90, 4);
                else tft.drawCentreString("2FA: Sync Time via Web UI", 160, 95, 2);
            }

            // Draw Next Action Hint
            tft.setTextColor(TFT_GREEN, TFT_BLACK);
            if (e.totp.length() > 0) {
                if (!g_typeTotpNext) tft.drawCentreString("Btn: Type Pass -> Then 2FA", 160, 130, 2);
                else tft.drawCentreString("Btn: Type 2FA Code", 160, 130, 2);
            } else {
                tft.drawCentreString("Btn: Type Password", 160, 130, 2);
            }

            tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
            tft.drawCentreString(String(g_selectedIndex + 1) + " / " + String(g_entries.size()), 160, 150, 2);
        }
    }
  }
}

// ================================ Setup ====================================
void setup() {
  Serial.begin(115200);

  pinMode(BTN_NAV, INPUT_PULLUP);
  pinMode(BTN_TYPE, INPUT_PULLUP);
  pinMode(PIN_POWER_ON, OUTPUT); digitalWrite(PIN_POWER_ON, HIGH); delay(100);

  USB.begin(); usbKeyboard.begin();

  tft.init(); tft.setRotation(1);
  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, HIGH);

  tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.drawCentreString("BOOTING SYSTEM...", 160, 80, 2); delay(500);

  if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");
  loadSettings();

  WiFi.mode(WIFI_AP); WiFi.softAPConfig(apIP,apIP,IPAddress(255,255,255,0));
  WiFi.softAP(AP_SSID, AP_PASS, 1, g_apHidden ? 1 : 0);

  dns.start(53,"*",apIP); startBleIfEnabled();

  g_bootPass = genPassword(12);

  const char* hk[] = { "Cookie" }; server.collectHeaders(hk,1);

  server.on("/",            HTTP_GET,  handleRoot);
  server.on("/setup",       HTTP_POST, handleSetup);
  server.on("/unlock",      HTTP_POST, handleUnlock);
  server.on("/logout",      HTTP_GET,  handleLogout);
  server.on("/api/status",  HTTP_GET,  apiStatus);
  server.on("/api/time",    HTTP_POST, apiTime);
  server.on("/api/list",    HTTP_GET,  apiList);
  server.on("/api/secret",  HTTP_GET,  apiSecret);
  server.on("/api/add",     HTTP_POST, apiAdd);
  server.on("/api/update",  HTTP_POST, apiUpdate);
  server.on("/api/delete",  HTTP_POST, apiDelete);
  server.on("/api/type",    HTTP_POST, apiType);
  server.on("/api/fav",     HTTP_POST, apiFav);
  server.on("/api/export",  HTTP_GET,  apiExport);
  server.on("/api/setble",  HTTP_POST, apiSetBle);
  server.on("/api/setup_decoy", HTTP_POST, apiSetupDecoy);
  server.onNotFound(handleNotFound);

  server.begin(); g_lastWebMs = millis();
}

// ================================ Loop =====================================
void loop() {
  dns.processNextRequest();
  server.handleClient();

  if (g_unlocked && (millis()-g_lastSeen > LOCK_MS)) lockVault();

  if (AP_TIMEOUT_MIN>0 && !g_apOff && (millis()-g_lastWebMs > AP_TIMEOUT_MIN*60000UL)) {
    WiFi.softAPdisconnect(true); g_apOff=true;
  }

  if (!g_unlocked) {
    if (digitalRead(BTN_TYPE) == LOW && (millis() - lastBtnType > 1000)) {
        typeText(g_bootPass, 12); lastBtnType = millis();
    }
  } else {
    bool btnNavCurrent = digitalRead(BTN_NAV);
    bool btnTypeCurrent = digitalRead(BTN_TYPE);
    bool isScreensaver = (millis() - g_lastSeen > SAVER_MS);

    if (isScreensaver) {
        if ((btnNavCurrent == LOW && btnNavLast == HIGH) || (btnTypeCurrent == LOW && (millis() - lastBtnType > 1000))) {
            g_lastSeen = millis(); btnNavLast = btnNavCurrent; lastBtnType = millis(); updateScreenUI(true);
        } else { btnNavLast = btnNavCurrent; }
    } else if (!g_entries.empty()) {

        // Navigation (Short/Long/Hold Press)
        if (btnNavCurrent == LOW && btnNavLast == HIGH) {
            btnNavPressTime = millis(); lastFastScroll = millis();
        }
        else if (btnNavCurrent == LOW && btnNavLast == LOW) {
            // FAST SCROLL LOGIC
            if (millis() - btnNavPressTime > 800) {
                if (millis() - lastFastScroll > 150) {
                    g_selectedIndex = (g_selectedIndex + 1) % g_entries.size();
                    g_lastSeen = millis(); g_typeTotpNext = false;
                    updateScreenUI(true);
                    lastFastScroll = millis();
                }
            }
        }
        else if (btnNavCurrent == HIGH && btnNavLast == LOW) {
            uint32_t pressDuration = millis() - btnNavPressTime;
            if (pressDuration > 50 && pressDuration <= 800) {
                // Regular Short Press
                g_selectedIndex = (g_selectedIndex + 1) % g_entries.size();
                g_lastSeen = millis(); g_typeTotpNext = false; updateScreenUI(true);
            }
        }
        btnNavLast = btnNavCurrent;

        // Typing Logic
        if (btnTypeCurrent == LOW && (millis() - lastBtnType > 1000)) {
            Entry& currentEntry = g_entries[g_selectedIndex];
            if (!g_typeTotpNext) {
                doType(&currentEntry, "pass");
                if (currentEntry.totp.length() > 0) g_typeTotpNext = true;
            } else {
                doType(&currentEntry, "totp"); g_typeTotpNext = false;
            }
            lastBtnType = millis(); g_lastSeen = millis(); updateScreenUI(true);
        }
    } else { btnNavLast = btnNavCurrent; }
  }
  updateScreenUI();
}
