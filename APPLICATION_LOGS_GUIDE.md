# Application Logs Collection Guide

## Overview

This document provides comprehensive guidance on collecting, parsing, and analyzing logs from common enterprise applications. Each section covers log locations, collection methods, parsing strategies, and detection rules.

---

## Section 1: Remote Access Tools

### 1.1 AnyDesk

**Risk Level:** HIGH - Commonly abused for unauthorized access

**Log Locations:**
```
Windows:
  - C:\ProgramData\AnyDesk\trace*.txt
  - %APPDATA%\AnyDesk\trace*.txt
  - Windows Event Log: Application log (Source: AnyDesk)
  - Registry: HKLM\SOFTWARE\AnyDesk, HKCU\SOFTWARE\AnyDesk

Linux:
  - ~/.anydesk/trace*.txt
  - /var/log/anydesk*.log
  - /var/log/syslog (anydesk entries)

macOS:
  - ~/.anydesk/trace*.txt
  - /Library/Logs/AnyDesk/
  - Console.app (search "AnyDesk")
```

**Collection Method:**
```bash
# Windows PowerShell
Get-ChildItem "C:\ProgramData\AnyDesk\trace*.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\anydesk_logs\"
Get-ChildItem "$env:APPDATA\AnyDesk\trace*.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\anydesk_logs\"
reg export HKLM\SOFTWARE\AnyDesk "$env:TEMP\anydesk_registry_hklm.reg" 2>$null
reg export HKCU\SOFTWARE\AnyDesk "$env:TEMP\anydesk_registry_hkcu.reg" 2>$null
wevtutil epl Application "$env:TEMP\anydesk_application.evtx" /q:"*[System[Provider[@Name='AnyDesk']]]"

# Linux
mkdir -p /tmp/anydesk_logs
cp ~/.anydesk/trace*.txt /tmp/anydesk_logs/ 2>/dev/null
cp /var/log/anydesk*.log /tmp/anydesk_logs/ 2>/dev/null
grep -i anydesk /var/log/syslog > /tmp/anydesk_logs/syslog_anydesk.log 2>/dev/null

# macOS
mkdir -p /tmp/anydesk_logs
cp ~/.anydesk/trace*.txt /tmp/anydesk_logs/ 2>/dev/null
cp -R /Library/Logs/AnyDesk/* /tmp/anydesk_logs/ 2>/dev/null
```

**Key Events to Monitor:**
- Incoming connection established
- Outgoing connection to unknown ID
- File transfer initiated
- Chat session started
- Permission elevation requested
- Unattended access enabled

**Detection Rules:**
```yaml
category: Remote Access - AnyDesk
rules:
  - name: AnyDesk Incoming Connection
    description: AnyDesk incoming connection established
    artifact_type: evtx
    query: "evtx.event_id:1 AND message:*AnyDesk* AND message:*incoming*"
    threshold: 1

  - name: AnyDesk After Hours Access
    description: AnyDesk connection outside business hours
    artifact_type: evtx
    query: "evtx.event_id:1 AND message:*AnyDesk* AND (message:*connected* OR message:*session*)"
    threshold: 1

  - name: AnyDesk File Transfer
    description: File transfer via AnyDesk detected
    artifact_type: evtx
    query: "evtx.event_id:1 AND message:*AnyDesk* AND message:*file transfer*"
    threshold: 1

  - name: AnyDesk Registry Installation
    description: AnyDesk installed or registry modified
    artifact_type: registry
    query: "registry.key:*\\\\AnyDesk* AND (registry.value:*Service* OR registry.value:*InstallPath*)"
    threshold: 1
```

**Parser Plugin:** Create plugins/anydesk/anydesk_plugin.py
- Parse trace*.txt files (tab-separated format)
- Extract: timestamp, session_id, remote_id, action, duration
- Index to Elasticsearch with artifact_type: anydesk

---

### 1.2 TeamViewer

**Risk Level:** HIGH - Frequently used in social engineering attacks

**Log Locations:**
```
Windows:
  - C:\Program Files\TeamViewer\TeamViewer15_Logfile.log
  - C:\Program Files\TeamViewer\Connections_incoming.txt
  - C:\Program Files\TeamViewer\Connections_outgoing.txt
  - %APPDATA%\TeamViewer\*.log
  - Windows Event Log: Application (Source: TeamViewer)

Linux:
  - /var/log/teamviewer*.log
  - ~/.teamviewer/*.log

macOS:
  - /Library/Logs/TeamViewer/*.log
  - ~/Library/Logs/TeamViewer/*.log
```

**Collection Method:**
```bash
# Windows PowerShell
Get-ChildItem "C:\Program Files\TeamViewer\*Logfile*.log" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\teamviewer_logs\"
Get-ChildItem "C:\Program Files\TeamViewer\Connections_*.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\teamviewer_logs\"
Get-ChildItem "$env:APPDATA\TeamViewer\*.log" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\teamviewer_logs\"

# Linux
mkdir -p /tmp/teamviewer_logs
cp /var/log/teamviewer*.log /tmp/teamviewer_logs/ 2>/dev/null
cp ~/.teamviewer/*.log /tmp/teamviewer_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/teamviewer_logs
cp -R /Library/Logs/TeamViewer/* /tmp/teamviewer_logs/ 2>/dev/null
cp -R ~/Library/Logs/TeamViewer/* /tmp/teamviewer_logs/ 2>/dev/null
```

**Key Events to Monitor:**
- Remote control session started
- File transfer session
- VPN connection established
- Meeting session started
- License type changed
- Password reset

**Detection Rules:**
```yaml
category: Remote Access - TeamViewer
rules:
  - name: TeamViewer New Installation
    description: TeamViewer software installed
    artifact_type: evtx
    query: "evtx.event_id:1033 OR evtx.event_id:1034 OR evtx.event_id:1035"
    threshold: 1

  - name: TeamViewer Incoming Connection
    description: TeamViewer incoming remote control session
    artifact_type: evtx
    query: "message:*TeamViewer* AND message:*Incoming connection*"
    threshold: 1

  - name: TeamViewer Outgoing Connection
    description: TeamViewer outgoing remote control session
    artifact_type: evtx
    query: "message:*TeamViewer* AND message:*Outgoing connection*"
    threshold: 1

  - name: TeamViewer File Transfer
    description: TeamViewer file transfer detected
    artifact_type: evtx
    query: "message:*TeamViewer* AND message:*File transfer*"
    threshold: 1
```

---

### 1.3 Splashtop

**Risk Level:** HIGH - Remote access with screen recording capability

**Log Locations:**
```
Windows:
  - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRServer_log*.txt
  - C:\ProgramData\Splashtop\*.log
  - Windows Event Log: Application (Source: Splashtop)

macOS:
  - /Library/Application Support/Splashtop/Logs/
  - ~/Library/Logs/Splashtop/
```

**Collection Method:**
```bash
# Windows PowerShell
Get-ChildItem "C:\Program Files (x86)\Splashtop\*\*log*.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\splashtop_logs\"
Get-ChildItem "C:\ProgramData\Splashtop\*.log" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\splashtop_logs\"

# macOS
mkdir -p /tmp/splashtop_logs
cp -R "/Library/Application Support/Splashtop/Logs/"/* /tmp/splashtop_logs/ 2>/dev/null
cp -R ~/Library/Logs/Splashtop/* /tmp/splashtop_logs/ 2>/dev/null
```

---

### 1.4 LogMeIn

**Risk Level:** HIGH - Enterprise remote access

**Log Locations:**
```
Windows:
  - C:\Program Files\LogMeIn\x86\Logs\
  - C:\Program Files\LogMeIn\x64\Logs\
  - Windows Event Log: Application (Source: LogMeIn)

macOS:
  - /Library/Logs/LogMeIn/
```

---

### 1.5 RustDesk

**Risk Level:** MEDIUM - Open source, can be self-hosted

**Log Locations:**
```
Windows:
  - C:\Program Files\RustDesk\debug.log
  - %APPDATA%\RustDesk\log\*.log

Linux:
  - ~/.rustdesk/log/*.log

macOS:
  - ~/Library/Logs/RustDesk/
```

---

## Section 2: Communication Tools

### 2.1 Skype

**Risk Level:** MEDIUM - Data exfiltration channel

**Log Locations:**
```
Windows:
  - %APPDATA%\Skype\<username>\main.db (SQLite database)
  - %APPDATA%\Skype\<username>\main.db-shm
  - %APPDATA%\Skype\<username>\main.db-wal
  - %LOCALAPPDATA%\Skype\Setup.log
  - Windows Event Log: Application

Linux:
  - ~/.Skype/<username>/main.db
  - ~/.skypeforlinux/logs/

macOS:
  - ~/Library/Application Support/Skype/<username>/main.db
  - ~/Library/Logs/Skype/
```

**Collection Method:**
```bash
# Windows PowerShell
$username = $env:USERNAME
Copy-Item "$env:APPDATA\Skype\$username\main.db*" -Destination "$env:TEMP\skype_logs\" -ErrorAction SilentlyContinue
Copy-Item "$env:LOCALAPPDATA\Skype\Setup.log" -Destination "$env:TEMP\skype_logs\" -ErrorAction SilentlyContinue

# Linux
mkdir -p /tmp/skype_logs
cp ~/.Skype/$USER/main.db* /tmp/skype_logs/ 2>/dev/null
cp ~/.skypeforlinux/logs/* /tmp/skype_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/skype_logs
cp ~/Library/Application\ Support/Skype/$USER/main.db* /tmp/skype_logs/ 2>/dev/null
cp -R ~/Library/Logs/Skype/* /tmp/skype_logs/ 2>/dev/null
```

**Key Events to Monitor:**
- New contact added
- File transfer received/sent
- Call initiated (especially international)
- Screen sharing session
- Message with attachment

**SQLite Tables of Interest:**
- ChatMsg (messages with timestamps)
- Contacts (contact list)
- Transfers (file transfers)
- Calls (call history)

---

### 2.2 Microsoft Teams

**Risk Level:** MEDIUM - Corporate communication, data leakage risk

**Log Locations:**
```
Windows:
  - %APPDATA%\Microsoft\Teams\logs.txt
  - %APPDATA%\Microsoft\Teams\Service Worker\CacheStorage\
  - %LOCALAPPDATA%\Microsoft\Teams\current\logs.txt
  - Windows Event Log: Application

Linux:
  - ~/.config/Microsoft/Microsoft Teams/logs.txt

macOS:
  - ~/Library/Application Support/Microsoft/Teams/logs.txt
  - ~/Library/Logs/Microsoft Teams/
```

**Collection Method:**
```bash
# Windows PowerShell
Get-ChildItem "$env:APPDATA\Microsoft\Teams\logs.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\teams_logs\"
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Teams\current\logs.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\teams_logs\"

# Linux
mkdir -p /tmp/teams_logs
cp ~/.config/Microsoft/Microsoft\ Teams/logs.txt /tmp/teams_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/teams_logs
cp ~/Library/Application\ Support/Microsoft/Teams/logs.txt /tmp/teams_logs/ 2>/dev/null
cp -R ~/Library/Logs/Microsoft\ Teams/* /tmp/teams_logs/ 2>/dev/null
```

---

### 2.3 Slack

**Risk Level:** MEDIUM - Corporate communication

**Log Locations:**
```
Windows:
  - %APPDATA%\Slack\logs\
  - %APPDATA%\Slack\Cache\
  - %APPDATA%\Slack\Local Storage\

Linux:
  - ~/.config/Slack/logs/
  - ~/.config/Slack/Cache/

macOS:
  - ~/Library/Logs/Slack/
  - ~/Library/Caches/com.tinyspeck.slackmacgap/
```

---

### 2.4 Zoom

**Risk Level:** LOW-MEDIUM - Video conferencing

**Log Locations:**
```
Windows:
  - %APPDATA%\Zoom\ZoomConsole.log
  - %APPDATA%\Zoom\logs\
  - %LOCALAPPDATA%\Zoom\logs\

macOS:
  - ~/Library/Logs/zoom.us/
  - ~/Library/Application Support/zoom.us/
```

---

### 2.5 Discord

**Risk Level:** MEDIUM - Often used for C2 and data exfiltration

**Log Locations:**
```
Windows:
  - %APPDATA%\discord\*.log
  - %LOCALAPPDATA%\discord\app-*\modules\discord_desktop_core-*\

Linux:
  - ~/.config/discord/logs/

macOS:
  - ~/Library/Application Support/discord/logs/
```

**Key Events to Monitor:**
- File upload (especially executables)
- Direct message from unknown user
- Server join (especially private servers)
- Screen share initiated
- Nitro gift received (potential malware delivery)

---

### 2.6 WhatsApp Desktop

**Risk Level:** LOW - End-to-end encrypted, limited log data

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Packages\Microsoft.WhatsAppDesktop_*\LocalState\logs\

macOS:
  - ~/Library/Containers/WhatsApp Desktop/Data/Library/Logs/
```

---

### 2.7 Telegram

**Risk Level:** MEDIUM - Encrypted, popular for C2

**Log Locations:**
```
Windows:
  - %APPDATA%\Telegram Desktop\log.txt
  - %APPDATA%\Telegram Desktop\tdata\ (encrypted session data)

Linux:
  - ~/.TelegramDesktop/log.txt
  - ~/.TelegramDesktop/tdata/

macOS:
  - ~/Library/Application Support/Telegram Desktop/log.txt
  - ~/Library/Application Support/Telegram Desktop/tdata/
```

---

## Section 3: Cloud Storage and Sync Tools

### 3.1 OneDrive

**Risk Level:** MEDIUM - Data exfiltration channel

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Microsoft\OneDrive\logs\
  - %LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe.log
  - Windows Event Log: Application (Source: OneDrive)
  - Registry: HKCU\SOFTWARE\Microsoft\OneDrive

Linux:
  - ~/.config/onedrive/logs/

macOS:
  - ~/Library/Logs/OneDrive/
```

**Collection Method:**
```bash
# Windows PowerShell
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\OneDrive\logs\" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\onedrive_logs\"
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\OneDrive\*.log" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\onedrive_logs\"

# Linux
mkdir -p /tmp/onedrive_logs
cp ~/.config/onedrive/logs/* /tmp/onedrive_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/onedrive_logs
cp -R ~/Library/Logs/OneDrive/* /tmp/onedrive_logs/ 2>/dev/null
```

**Key Events to Monitor:**
- Large file upload
- File sync to external account
- Sharing link created
- Files synced to new device
- Admin policy changed

**Detection Rules:**
```yaml
category: Cloud Storage - OneDrive
rules:
  - name: OneDrive Large File Upload
    description: Large file uploaded to OneDrive (potential exfiltration)
    artifact_type: evtx
    query: "message:*OneDrive* AND message:*upload* AND message:*MB*"
    threshold: 5

  - name: OneDrive External Share
    description: OneDrive file shared with external user
    artifact_type: evtx
    query: "message:*OneDrive* AND message:*share* AND message:*external*"
    threshold: 1

  - name: OneDrive New Device Sync
    description: OneDrive sync initiated from new device
    artifact_type: evtx
    query: "message:*OneDrive* AND message:*sync* AND message:*device*"
    threshold: 1
```

---

### 3.2 Google Drive

**Risk Level:** MEDIUM - Data exfiltration

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Google\DriveFS\logs\
  - %LOCALAPPDATA%\Google\Drive File Stream\logs\

macOS:
  - ~/Library/Logs/Google/DriveFS/
```

---

### 3.3 Dropbox

**Risk Level:** MEDIUM - Data exfiltration

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Dropbox\instance*\log.log
  - %APPDATA%\Dropbox\logs\

Linux:
  - ~/.dropbox-dist/log.log

macOS:
  - ~/Library/Logs/Dropbox/
```

---

### 3.4 Box

**Risk Level:** LOW-MEDIUM - Enterprise cloud storage

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Box\Box\logs\

macOS:
  - ~/Library/Logs/Box/
```

---

### 3.5 iCloud

**Risk Level:** LOW - Apple ecosystem sync

**Log Locations:**
```
Windows:
  - %APPDATA%\Apple Computer\iCloud\logs\

macOS:
  - ~/Library/Logs/icloud/
  - Console.app (search "icloud")
```

---

## Section 4: Security Tools (EDR/Antivirus)

### 4.1 Microsoft Defender

**Risk Level:** N/A - Security tool (logs should be PRESERVED)

**Important:** DO NOT disable. Collect logs for threat detection.

**Log Locations:**
```
Windows:
  - Windows Event Log: Microsoft-Windows-Windows Defender/Operational
  - Windows Event Log: Microsoft-Windows-Windows Defender/WHistler
  - C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\
  - PowerShell: Get-MpThreatDetection

Linux:
  - /var/log/wdavd.log

macOS:
  - /var/log/wdavd.log
```

**Collection Method:**
```bash
# Windows PowerShell - EXPORT DO NOT DISABLE
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "$env:TEMP\defender_operational.evtx"
wevtutil epl "Microsoft-Windows-Windows Defender/WHistler" "$env:TEMP\defender_whistler.evtx"
Get-MpThreatDetection | Export-Csv "$env:TEMP\defender_threats.csv" -NoTypeInformation
Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\" -Recurse | Copy-Item -Destination "$env:TEMP\defender_scans\" -ErrorAction SilentlyContinue

# Get Defender status (should be ENABLED)
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntiSpywareEnabled, RealTimeProtectionEnabled | Export-Csv "$env:TEMP\defender_status.csv"
```

**Key Events to Monitor:**
- Threat detected and quarantined
- Real-time protection disabled (ALERT)
- Exclusion added (potential persistence)
- Signature update failed
- Scan completed

**Detection Rules:**
```yaml
category: Security Tool - Microsoft Defender
rules:
  - name: Defender Real-Time Protection Disabled
    description: CRITICAL - Microsoft Defender real-time protection was disabled
    artifact_type: evtx
    query: "evtx.source:Microsoft-Windows-Windows Defender/Operational AND evtx.event_id:5001"
    threshold: 1

  - name: Defender Exclusion Added
    description: File/folder exclusion added to Defender (potential persistence)
    artifact_type: evtx
    query: "evtx.source:Microsoft-Windows-Windows Defender/Operational AND evtx.event_id:5007"
    threshold: 1

  - name: Defender Threat Detected
    description: Microsoft Defender detected malware or unwanted software
    artifact_type: evtx
    query: "evtx.source:Microsoft-Windows-Windows Defender/Operational AND evtx.event_id:1116 OR evtx.event_id:1117"
    threshold: 1

  - name: Defender Signature Update Failed
    description: Defender failed to update malware signatures
    artifact_type: evtx
    query: "evtx.source:Microsoft-Windows-Windows Defender/Operational AND evtx.event_id:2001"
    threshold: 1
```

---

### 4.2 CrowdStrike Falcon

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: CrowdStrike)
  - C:\ProgramData\CrowdStrike\Logs\
  - PowerShell: Get-WinEvent -LogName "Application" | Where-Object {$_.ProviderName -eq "CrowdStrike"}

Linux:
  - /var/log/CrowdStrike/

macOS:
  - /var/log/CrowdStrike/
```

**Collection Method:**
```bash
# Windows PowerShell
wevtutil epl Application "$env:TEMP\crowdstrike_application.evtx" /q:"*[System[Provider[@Name='CrowdStrike']]]"
Get-ChildItem "C:\ProgramData\CrowdStrike\Logs\" -ErrorAction SilentlyContinue | Copy-Item -Destination "$env:TEMP\crowdstrike_logs\" -ErrorAction SilentlyContinue

# Linux
mkdir -p /tmp/crowdstrike_logs
cp /var/log/CrowdStrike/* /tmp/crowdstrike_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/crowdstrike_logs
cp /var/log/CrowdStrike/* /tmp/crowdstrike_logs/ 2>/dev/null
```

---

### 4.3 SentinelOne

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: SentinelOne)
  - C:\ProgramData\Sentinel\Logs\

Linux:
  - /opt/SentinelOne/Logs/

macOS:
  - /Library/Application Support/Sentinel/Logs/
```

---

### 4.4 Carbon Black

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: Carbon Black)
  - C:\ProgramData\Carbon Black\Logs\

Linux:
  - /var/log/carbonblack/

macOS:
  - /Library/Application Support/Carbon Black/Logs/
```

---

### 4.5 Symantec Endpoint Protection

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: Symantec Endpoint Protection)
  - C:\ProgramData\Symantec\Symantec Endpoint Protection\Logs\

Linux:
  - /var/log/symantec/

macOS:
  - /Library/Application Support/Symantec/Logs/
```

---

### 4.6 McAfee Endpoint Security

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: McAfee)
  - C:\ProgramData\McAfee\Endpoint Security\Logs\

macOS:
  - /Library/Application Support/McAfee/Logs/
```

---

### 4.7 ESET Endpoint Security

**Risk Level:** N/A - Security tool (PRESERVE logs)

**Log Locations:**
```
Windows:
  - Windows Event Log: Application (Source: ESET)
  - C:\ProgramData\ESET\ESET Security\Logs\

Linux:
  - /var/log/eset/

macOS:
  - /Library/Application Support/ESET/Logs/
```

---

## Section 5: Browser Logs

### 5.1 Google Chrome

**Risk Level:** MEDIUM - Data exfiltration, credential theft

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\History (SQLite)
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies (SQLite)
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data (SQLite)
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data (SQLite)
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\
  - %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies

Linux:
  - ~/.config/google-chrome/Default/

macOS:
  - ~/Library/Application Support/Google/Chrome/Default/
```

**Collection Method:**
```bash
# Windows PowerShell - Chrome must be CLOSED
Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\"
New-Item -ItemType Directory -Path "$env:TEMP\chrome_logs\" -Force
Copy-Item "$chromePath\History" "$env:TEMP\chrome_logs\" -ErrorAction SilentlyContinue
Copy-Item "$chromePath\Bookmarks" "$env:TEMP\chrome_logs\" -ErrorAction SilentlyContinue
Copy-Item "$chromePath\Cookies" "$env:TEMP\chrome_logs\" -ErrorAction SilentlyContinue
Copy-Item "$chromePath\Login Data" "$env:TEMP\chrome_logs\" -ErrorAction SilentlyContinue
Copy-Item "$chromePath\Web Data" "$env:TEMP\chrome_logs\" -ErrorAction SilentlyContinue
Get-ChildItem "$chromePath\Extensions\" -Recurse -File | Copy-Item -Destination "$env:TEMP\chrome_logs\extensions\" -ErrorAction SilentlyContinue

# Linux
mkdir -p /tmp/chrome_logs
cp ~/.config/google-chrome/Default/{History,Bookmarks,Cookies,Login Data,Web Data} /tmp/chrome_logs/ 2>/dev/null
cp -R ~/.config/google-chrome/Default/Extensions /tmp/chrome_logs/ 2>/dev/null

# macOS
mkdir -p /tmp/chrome_logs
cp ~/Library/Application\ Support/Google/Chrome/Default/{History,Bookmarks,Cookies,Login Data,Web Data} /tmp/chrome_logs/ 2>/dev/null
cp -R ~/Library/Application\ Support/Google/Chrome/Default/Extensions /tmp/chrome_logs/ 2>/dev/null
```

**Key Data to Extract:**
- Browsing history (urls, timestamps, visit count)
- Download history
- Installed extensions (potential malware)
- Saved credentials
- Autofill data
- Search queries

---

### 5.2 Mozilla Firefox

**Risk Level:** MEDIUM

**Log Locations:**
```
Windows:
  - %APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite (history/bookmarks)
  - %APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json (saved passwords)
  - %APPDATA%\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite
  - %APPDATA%\Mozilla\Firefox\Profiles\<profile>\prefs.js

Linux:
  - ~/.mozilla/firefox/<profile>/

macOS:
  - ~/Library/Application Support/Firefox/Profiles/<profile>/
```

---

### 5.3 Microsoft Edge

**Risk Level:** MEDIUM

**Log Locations:**
```
Windows:
  - %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History
  - %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks
  - %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies
  - %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

macOS:
  - ~/Library/Application Support/Microsoft Edge/Default/
```

---

### 5.4 Safari

**Risk Level:** LOW

**Log Locations:**
```
macOS:
  - ~/Library/Safari/History.db
  - ~/Library/Safari/Bookmarks.plist
  - ~/Library/Safari/Cookies/Cookies.binarycookies
  - ~/Library/Containers/com.apple.Safari/Data/Library/Safari/
```

---

## Section 6: System and Application Logs

### 6.1 Windows Event Logs (Critical)

**Collection Method:**
```powershell
# Export ALL event logs
$logNames = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object -ExpandProperty LogName
foreach ($log in $logNames) {
    wevtutil epl $log "$env:TEMP\windows_logs\$log.evtx" 2>$null
}

# Critical logs to always collect
$criticalLogs = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-SMBClient/Security",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational"
)

foreach ($log in $criticalLogs) {
    wevtutil epl $log "$env:TEMP\windows_logs\$($log.Replace('/','_')).evtx" 2>$null
}
```

---

### 6.2 Linux System Logs

**Collection Method:**
```bash
mkdir -p /tmp/system_logs

# System logs
cp /var/log/syslog /tmp/system_logs/ 2>/dev/null
cp /var/log/auth.log /tmp/system_logs/ 2>/dev/null
cp /var/log/kern.log /tmp/system_logs/ 2>/dev/null
cp /var/log/dmesg /tmp/system_logs/ 2>/dev/null
cp /var/log/boot.log /tmp/system_logs/ 2>/dev/null

# Application logs
cp /var/log/cron /tmp/system_logs/ 2>/dev/null
cp /var/log/mail.log /tmp/system_logs/ 2>/dev/null
cp /var/log/apache2/*.log /tmp/system_logs/ 2>/dev/null
cp /var/log/nginx/*.log /tmp/system_logs/ 2>/dev/null

# Journalctl (systemd systems)
journalctl --since "7 days ago" > /tmp/system_logs/journalctl_7days.log 2>/dev/null
journalctl -k --since "7 days ago" > /tmp/system_logs/journalctl_kernel_7days.log 2>/dev/null

# History files
cp ~/.bash_history /tmp/system_logs/ 2>/dev/null
cp ~/.zsh_history /tmp/system_logs/ 2>/dev/null
cp /root/.bash_history /tmp/system_logs/ 2>/dev/null
```

---

### 6.3 macOS System Logs

**Collection Method:**
```bash
mkdir -p /tmp/system_logs

# Unified logs (last 7 days)
log show --last 7d > /tmp/system_logs/unified_logs_7d.log 2>/dev/null

# Specific log types
log show --predicate 'eventMessage contains "error"' --last 7d > /tmp/system_logs/errors_7d.log 2>/dev/null
log show --predicate 'process == "ssh"' --last 7d > /tmp/system_logs/ssh_7d.log 2>/dev/null

# Traditional logs
cp /var/log/system.log /tmp/system_logs/ 2>/dev/null
cp /var/log/install.log /tmp/system_logs/ 2>/dev/null

# History
cp ~/.bash_history /tmp/system_logs/ 2>/dev/null
cp ~/.zsh_history /tmp/system_logs/ 2>/dev/null
```

---

## Section 7: Applications to DISABLE During Investigation

**WARNING:** Only disable these applications with proper authorization and documentation. Some may be required for business operations.

### 7.1 Applications to Consider Disabling

| Application | Reason | Risk if Left Enabled | Disable Method |
|-------------|--------|---------------------|----------------|
| AnyDesk | Unauthorized remote access | Attacker can regain access | Stop service, block firewall |
| TeamViewer | Unauthorized remote access | Attacker can regain access | Stop service, block firewall |
| Splashtop | Unauthorized remote access | Attacker can regain access | Stop service |
| LogMeIn | Unauthorized remote access | Attacker can regain access | Stop service |
| RustDesk | Unauthorized remote access | Attacker can regain access | Stop process |
| Chrome Remote Desktop | Unauthorized remote access | Attacker can regain access | Disable extension |
| Windows Quick Assist | Unauthorized remote access | Built-in Windows tool | Disable via Group Policy |
| Microsoft Remote Desktop | Legitimate but monitor | Can be abused | Monitor via Event ID 21-25 |
| VNC (all variants) | Unauthorized remote access | Common attack tool | Stop service |
| Dropbox | Data exfiltration | Auto-sync can destroy evidence | Quit application |
| Google Drive | Data exfiltration | Auto-sync | Quit application |
| OneDrive | Data exfiltration | Microsoft tool but can exfil | Pause sync |
| Telegram | C2 communication | Encrypted, hard to monitor | Quit application |
| Discord | C2 communication | Popular for C2 | Quit application |
| Skype | Data exfiltration | File transfer | Quit application |
| WhatsApp Desktop | Data exfiltration | Encrypted | Quit application |
| BitTorrent clients | Malware distribution | Can download additional payloads | Stop process |
| PowerShell (constrained) | Attack tool | Living off the land | Enable constrained mode |
| Windows Script Host | Attack tool | VBScript/JScript execution | Disable via registry |

### 7.2 Disable Commands

**Windows PowerShell:**
```powershell
# Stop remote access services
Stop-Service AnyDesk -Force -ErrorAction SilentlyContinue
Stop-Service TeamViewer -Force -ErrorAction SilentlyContinue
Stop-Service LogMeIn -Force -ErrorAction SilentlyContinue
Stop-Service "Splashtop*" -Force -ErrorAction SilentlyContinue

# Block remote access in firewall
New-NetFirewallRule -DisplayName "Block AnyDesk" -Direction Outbound -Action Block -Program "C:\Program Files (x86)\AnyDesk\anydesk.exe" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block TeamViewer" -Direction Outbound -Action Block -Program "C:\Program Files\TeamViewer\TeamViewer.exe" -ErrorAction SilentlyContinue

# Disable Windows Quick Assist
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableQuickAssist" /t REG_DWORD /d 1 /f

# Disable Windows Script Host
reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f

# Pause OneDrive
"$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe" /pause

# Kill common processes
Get-Process discord, telegram, skype, whatsapp -ErrorAction SilentlyContinue | Stop-Process -Force
```

**Linux:**
```bash
# Stop remote access services
systemctl stop anydesk
systemctl stop teamviewerd
systemctl stop logmein
systemctl disable anydesk
systemctl disable teamviewerd

# Block in firewall
iptables -A OUTPUT -p tcp --dport 6568 -j DROP  # AnyDesk
iptables -A OUTPUT -p tcp --dport 5938 -j DROP  # TeamViewer

# Kill processes
pkill -9 telegram-desktop
pkill -9 discord
pkill -9 skypeforlinux
```

---

## Section 8: Detection Rules for Application Activity

```yaml
category: Application Activity
rules:
  - name: Remote Access Tool Installed
    description: Common remote access software was installed
    artifact_type: evtx
    query: "evtx.event_id:1033 OR evtx.event_id:1034 OR evtx.event_id:1035 AND (message:*AnyDesk* OR message:*TeamViewer* OR message:*Splashtop* OR message:*LogMeIn*)"
    threshold: 1

  - name: Remote Access After Hours
    description: Remote access tool used outside business hours
    artifact_type: evtx
    query: "(message:*AnyDesk* OR message:*TeamViewer* OR message:*RDP*) AND (message:*connected* OR message:*session*)"
    threshold: 1

  - name: Cloud Storage Large Upload
    description: Large file uploaded to cloud storage service
    artifact_type: evtx
    query: "(message:*OneDrive* OR message:*Dropbox* OR message:*Google Drive*) AND message:*upload*"
    threshold: 10

  - name: Security Tool Disabled
    description: Antivirus or EDR protection was disabled
    artifact_type: evtx
    query: "(message:*Defender* OR message:*CrowdStrike* OR message:*Symantec*) AND (message:*disabled* OR message:*stopped* OR message:*turned off*)"
    threshold: 1

  - name: Browser Extension Installed
    description: New browser extension was added
    artifact_type: evtx
    query: "message:*Chrome* AND message:*extension* AND message:*install*"
    threshold: 1

  - name: PowerShell Download Cradle
    description: PowerShell downloaded and executed script
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*DownloadString* OR message:*DownloadFile* OR message:*Invoke-WebRequest*)"
    threshold: 1

  - name: Scheduled Task Created by Remote Tool
    description: Scheduled task created by remote access software
    artifact_type: evtx
    query: "evtx.event_id:4698 AND (message:*AnyDesk* OR message:*TeamViewer* OR message:*Splashtop*)"
    threshold: 1

  - name: Registry Run Key Modified by Unknown App
    description: Application added to startup via registry
    artifact_type: registry
    query: "registry.key:*\\\\CurrentVersion\\\\Run* AND NOT registry.value:*(Microsoft|Windows|Adobe|Google)*"
    threshold: 1
```

---

## Section 9: Implementation Priority

### Immediate (Week 1)
1. Create collector scripts for remote access tool logs (AnyDesk, TeamViewer)
2. Create parser plugins for AnyDesk trace files
3. Create parser plugins for TeamViewer log files
4. Add detection rules for remote access activity

### Short-Term (Week 2-3)
5. Create browser log collection scripts (Chrome, Firefox, Edge)
6. Create parser plugins for browser SQLite databases
7. Add cloud storage detection rules
8. Create EDR log preservation scripts

### Medium-Term (Month 2)
9. Create communication tool parsers (Slack, Teams, Discord)
10. Implement application whitelist monitoring
11. Add unauthorized software detection
12. Create automated disable scripts for high-risk applications

---

## Section 10: Plugin Implementation Examples

### Example: AnyDesk Parser Plugin

**File:** plugins/anydesk/anydesk_plugin.py

```python
"""AnyDesk trace file parser."""
from plugins.base_plugin import BasePlugin, PluginContext, PluginParseError
import re
from datetime import datetime

class AnyDeskPlugin(BasePlugin):
    PLUGIN_NAME = "AnyDesk"
    SUPPORTED_FILES = ["trace*.txt"]
    
    def parse(self):
        """Parse AnyDesk trace files."""
        with open(self.context.source_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Format: YYYY-MM-DD HH:MM:SS.mmm - ID - Level - Message
                match = re.match(
                    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+-\s+(\d+)\s+-\s+(\w+)\s+-\s+(.+)',
                    line.strip()
                )
                if match:
                    timestamp, session_id, level, message = match.groups()
                    
                    yield {
                        "timestamp": timestamp,
                        "session_id": session_id,
                        "level": level,
                        "message": message,
                        "artifact_type": "anydesk",
                        "raw": {"line": line.strip()}
                    }
```

---

*End of Application Logs Guide*
