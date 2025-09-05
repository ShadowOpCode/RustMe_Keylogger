# RustMe Keylogger – Technical Analysis

**Author:** ShadowOpCode  
**Date:** 2025-08-31  
**Status:** Previously undocumented  
**Family:** RustMe (Windows Keylogger, x64)

---

## 📖 Overview
This repository contains the technical report, Indicators of Compromise (IoCs), and YARA detection rules for **RustMe**, a *previously undocumented 64-bit Windows keylogger*.  

RustMe installs a **low-level keyboard hook** (`SetWindowsHookExA`, `WH_KEYBOARD_LL`) to capture keystrokes across the desktop session, normalizes them via `GetKeyboardState`, `MapVirtualKeyA`, and `ToUnicode`, and exfiltrates logs through **Gmail SMTP** using libcurl.  

Persistence is achieved by dropping `DebugConfig.bat` and a `.lnk` file in the Startup folder. The malware enforces the US keyboard layout (`00000409`) to ensure consistent keystroke mapping.

---

## 🔬 Key Findings
- 64-bit Windows binary (MinGW)  
- Keylogging via `WH_KEYBOARD_LL` hook  
- Keystroke translation with `ToUnicode`  
- Forced US keyboard layout (`00000409`)  
- Exfiltration over Gmail SMTP (`smtp.gmail.com:587`, `serversreser@gmail.com`)  
- Persistence through `DebugConfig.bat` + `.lnk` in Startup  

---

## 🛡 Detection
### YARA Rules
- `RustMe_Keylogger` – high-confidence detection of RustMe samples

YARA rules are included in [`yara/`].

### MITRE ATT&CK Mapping
- **T1056.001** – Input Capture: Keylogging  
- **T1547.001** – Persistence: Startup Folder  
- **T1048.003** – Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (SMTP)  
- **T1027** – Obfuscated/Encoded Files

## ⚠️ Disclaimer
This research is provided for **educational and defensive purposes only**.  
Do not use any included samples, code, or IoCs for malicious activity.  
