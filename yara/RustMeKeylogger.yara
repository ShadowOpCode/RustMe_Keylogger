import "pe"

rule ShadowOpCode_RustMe_Keylogger_STRICT_v1
{
    meta:
        author      = "ShadowOpCode"
        description = "RustMe keylogger x64: WH_KEYBOARD_LL + libcurl SMTP (Gmail) + US layout + DebugConfig persistence"
        date        = "2025-08-31"
        confidence  = "high"
        tlp         = "CLEAR"
        reference   = "Callback fn + main orchestration as analyzed by ShadowOpCode"

    strings:
        // Exfiltration
        $smtp_url   = "smtp://smtp.gmail.com:587" ascii
        $gmail_dom  = "gmail.com" ascii
        $gmail_user = "serversreser@gmail.com" ascii
        $subject    = "Subject: Keylogger Report" ascii
        $libcurl    = "libcurl" ascii

        // keystroke translation
        $tou        = "ToUnicode" ascii
        $mapvk      = "MapVirtualKeyA" ascii
        $kbdstate   = "GetKeyboardState" ascii

        // Keyboard layout
        $load_hkl   = "LoadKeyboardLayoutA" ascii
        $hkl_us     = "00000409" ascii

        // Persistence and artifacts
        $dbg_bat    = "DebugConfig.bat" ascii
        $launcher   = "\\RustMeLauncher\\current" ascii

        // Debug banner
        $started    = "KeyLogger Started" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_64bit() and
        pe.imports("USER32.dll", "SetWindowsHookExA") and
        pe.imports("USER32.dll", "CallNextHookEx") and
        all of ($smtp_url, $gmail_dom, $libcurl) and
        1 of ($gmail_user, $subject) and
        all of ($tou, $mapvk, $kbdstate) and
        all of ($load_hkl, $hkl_us) and
        1 of ($dbg_bat, $launcher, $started)
}

rule ShadowOpCode_Win_Keylogger_SMTP_GENERIC_v1
{
    meta:
        author      = "ShadowOpCode"
        description = "Windows keylogger: WH_KEYBOARD_LL + ToUnicode + SMTP exfiltration (generic)"
        date        = "2025-08-31"
        confidence  = "medium"
        tlp         = "CLEAR"

    strings:
        // Hook and keystroke translation
        $tou        = "ToUnicode" ascii
        $mapvk      = "MapVirtualKeyA" ascii
        $kbdstate   = "GetKeyboardState" ascii

        // SMTP artifacts
        $smtp_scheme = "smtp://" ascii
        $header_subj = "Subject:" ascii

        // Key labels used in logs
        $lbl_back    = "(BACKSPACE)" ascii
        $lbl_tab     = "(TAB)" ascii
        $lbl_space   = "(SPACEBAR)" ascii
        $lbl_caps    = "(CAPS_LOCK)" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_64bit() and
        pe.imports("USER32.dll", "SetWindowsHookExA") and
        pe.imports("USER32.dll", "CallNextHookEx") and
        all of ($tou, $mapvk, $kbdstate) and
        $smtp_scheme and
        1 of ($header_subj, $lbl_back, $lbl_tab, $lbl_space, $lbl_caps)
}