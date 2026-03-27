# Detection Rules Expansion Proposal

## Current State Analysis

### ✅ Existing Rules (11 Categories, 67 Rules Total)

| Category | File | Rules | Status |
|----------|------|-------|--------|
| Anti-Forensics | 01_anti_forensics.yaml | 5 | ✅ Complete |
| Authentication | 02_authentication.yaml | 7 | ✅ Complete |
| Privilege Escalation | 03_privilege_escalation.yaml | 5 | ✅ Complete |
| Persistence | 04_persistence.yaml | 7 | ✅ Complete |
| Execution | 05_execution.yaml | 9 | ✅ Complete |
| Lateral Movement | 06_lateral_movement.yaml | 5 | ⚠️ Needs expansion |
| Defense Evasion | 07_defense_evasion.yaml | 6 | ⚠️ Needs expansion |
| Credential Access | 08_credential_access.yaml | 6 | ⚠️ Needs expansion |
| Discovery | 09_discovery.yaml | 5 | ⚠️ Needs expansion |
| Command & Control | 10_command_control.yaml | 6 | ⚠️ Needs expansion |
| Exfiltration | 11_exfiltration.yaml | 5 | ⚠️ Needs expansion |

### 📊 Artifact Type Coverage

| Artifact Type | Rules Supporting | Gaps |
|--------------|-----------------|------|
| EVTX (Windows Events) | 62 rules | ✅ Well covered |
| Suricata (Network) | 11 rules | ⚠️ Limited to alerts/flows |
| Sysmon | Via EVTX mapping | ⚠️ No dedicated Sysmon rules |
| Registry | 0 rules | ❌ Not covered |
| File System | 0 rules | ❌ Not covered |
| Browser History | 0 rules | ❌ Not covered |
| Prefetch | 0 rules | ❌ Not covered |
| LNK Files | 0 rules | ❌ Not covered |
| MFT | 0 rules | ❌ Not covered |
| Zeek/Bro | 0 rules | ❌ Not covered |

---

## 🆕 Proposed New Detection Rules

### 12. Initial Access (NEW CATEGORY)

**File:** `12_initial_access.yaml`

```yaml
category: Initial Access
rules:
  - name: Macro-Enabled Document Opened
    description: >-
      A Word/Excel/PowerPoint file with macros was opened.
      Common initial access vector for malware delivery.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND (message:*winword* OR message:*excel* OR message:*powerpnt*) AND (message:*.docm* OR message:*.xlsm* OR message:*.pptm*)"
    threshold: 1

  - name: Outlook Attachment Downloaded
    description: >-
      A file was downloaded from an Outlook email attachment.
      Review sender and attachment type for phishing indicators.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*outlook* AND (message:*TempOLK* OR message:*Content.Outlook*)"
    threshold: 1

  - name: Browser Downloaded Executable
    description: >-
      A web browser downloaded an executable file.
      May indicate drive-by download or malicious payload delivery.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND (message:*chrome* OR message:*firefox* OR message:*msedge*) AND (message:*.exe* OR message:*.bat* OR message:*.ps1*)"
    threshold: 1

  - name: OneNote Attachment Executed
    description: >-
      OneNote was used to open an attachment, a newer phishing technique.
      Attackers use OneNote to bypass email security filters.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*onenote* AND message:*embed*"
    threshold: 1

  - name: CHM File Executed
    description: >-
      A Compiled HTML Help file was executed.
      CHM files are used to deliver malware and execute scripts.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*.chm*"
    threshold: 1

  - name: ISO/VHD File Mounted
    description: >-
      A disk image file was mounted.
      Attackers use ISO/VHD files to bypass Mark of the Web security.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND (message:*mountvol* OR message:*DiskMount*) AND (message:*.iso* OR message:*.vhd* OR message:*.vhdx*)"
    threshold: 1
```

### 13. Impact (NEW CATEGORY)

**File:** `13_impact.yaml`

```yaml
category: Impact
rules:
  - name: Ransomware File Extension Change
    description: >-
      Multiple files were renamed with a new extension.
      Indicates ransomware encryption activity.
    artifact_type: evtx
    query: "evtx.event_id:4663 AND (message:*.encrypted* OR message:*.locked* OR message:*.crypto* OR message:*.ransom*)"
    threshold: 10

  - name: Mass File Deletion
    description: >-
      A large number of files were deleted in a short time.
      May indicate wiper malware or destructive attack.
    artifact_type: evtx
    query: "evtx.event_id:4660"
    threshold: 50

  - name: Boot Configuration Modified
    description: >-
      BCD (Boot Configuration Data) was modified.
      Attackers modify boot config to disable safe mode or recovery.
    artifact_type: evtx
    query: "evtx.event_id:4657 AND message:*BCD* OR message:*bootcfg*"
    threshold: 1

  - name: Windows Recovery Disabled
    description: >-
      Windows recovery options were disabled (bcdedit /set {default} recoveryenabled no).
      Common ransomware pre-encryption activity.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*bcdedit* AND message:*recoveryenabled*"
    threshold: 1

  - name: Volume Shadow Copy Deleted (Alternative)
    description: >-
      Alternative command for shadow copy deletion detected.
      Used by ransomware to prevent file recovery.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND (message:*vssadmin* OR message:*wmic* OR message:*powershell*) AND (message:*delete* OR message:*remove*) AND (message:*shadow* OR message:*vss*)"
    threshold: 1

  - name: Encrypting File System (EFS) Activity
    description: >-
      Files were encrypted using Windows EFS.
      Could indicate legitimate use or ransomware activity.
    artifact_type: evtx
    query: "evtx.event_id:5051 OR evtx.event_id:5052"
    threshold: 5
```

### 14. Resource Development (NEW CATEGORY)

**File:** `14_resource_development.yaml`

```yaml
category: Resource Development
rules:
  - name: Malicious Domain Accessed
    description: >-
      DNS query or network connection to a known malicious domain.
      Indicates potential C2 infrastructure or malware download.
    artifact_type: suricata
    query: "suricata.event_type:dns AND suricata.dns.domain:*malware* OR suricata.dns.domain:*c2* OR suricata.dns.domain:*evil*"
    threshold: 1

  - name: Rare User-Agent String
    description: >-
      HTTP request with an unusual or empty User-Agent string.
      Malware often uses custom or missing User-Agent headers.
    artifact_type: suricata
    query: "suricata.event_type:http AND (suricata.http.http_user_agent:* OR suricata.http.http_user_agent:*)"
    threshold: 5

  - name: TOR Network Activity
    description: >-
      Network traffic to or from TOR network nodes.
      TOR is commonly used for anonymous C2 communication.
    artifact_type: suricata
    query: "suricata.event_type:flow AND (suricata.dest_port:9001 OR suricata.dest_port:9030 OR suricata.dest_port:9150)"
    threshold: 1

  - name: Cryptocurrency Mining Pool Connection
    description: >-
      Network connection to known cryptocurrency mining pools.
      Indicates cryptojacking or unauthorized mining activity.
    artifact_type: suricata
    query: "suricata.event_type:flow AND (message:*stratum* OR message:*mining* OR message:*cryptonight* OR message:*monero*)"
    threshold: 1

  - name: Paste Site Access
    description: >-
      Connection to paste bin or code sharing sites.
      Attackers use these sites to host payloads and configurations.
    artifact_type: suricata
    query: "suricata.event_type:http AND (message:*pastebin* OR message:*ghostbin* OR message:*controlc* OR message:*hastebin*)"
    threshold: 1
```

### 15. Enhanced Sysmon Rules (NEW CATEGORY)

**File:** `15_sysmon_specific.yaml`

```yaml
category: Sysmon Specific
rules:
  - name: Sysmon Service Stopped
    description: >-
      Sysmon service was stopped.
      Attackers stop Sysmon to evade detection.
    artifact_type: evtx
    query: "evtx.event_id:7036 AND message:*Sysmon*"
    threshold: 1

  - name: Process Created with Hidden Window
    description: >-
      A process was started with a hidden window (Sysmon Event ID 1).
      Common technique for running malware in the background.
    artifact_type: evtx
    query: "evtx.event_id:1 AND message:*HiddenWindow=true*"
    threshold: 1

  - name: Network Connection by System Process
    description: >-
      A system process made a network connection (Sysmon Event ID 3).
      Review for unusual destinations or ports.
    artifact_type: evtx
    query: "evtx.event_id:3 AND (message:*System* OR message:*svchost*) AND NOT (suricata.dest_port:53 OR suricata.dest_port:80 OR suricata.dest_port:443)"
    threshold: 1

  - name: File Created in System Directory
    description: >-
      A file was created in Windows or System32 directory (Sysmon Event ID 11).
      Malware often drops files in system directories.
    artifact_type: evtx
    query: "evtx.event_id:11 AND (message:*\\\\Windows\\\\* OR message:*\\\\System32\\\\* OR message:*\\\\SysWOW64\\\\*)"
    threshold: 1

  - name: Registry Persistence Key Created
    description: >-
      A registry key was created in a known persistence location (Sysmon Event ID 13).
      Common locations include Run keys and service entries.
    artifact_type: evtx
    query: "evtx.event_id:13 AND (message:*\\\\CurrentVersion\\\\Run* OR message:*\\\\CurrentVersion\\\\RunOnce* OR message:*\\\\Control\\\\Services*)"
    threshold: 1

  - name: Process Access to Sensitive Process
    description: >-
      A process opened another process (Sysmon Event ID 10).
      Review for credential dumping or process injection.
    artifact_type: evtx
    query: "evtx.event_id:10 AND (message:*lsass* OR message:*sam* OR message:*ntds*)"
    threshold: 1

  - name: DNS Query to Rare TLD
    description: >-
      DNS query to an unusual top-level domain (Sysmon Event ID 22).
      Malware often uses rare TLDs for C2.
    artifact_type: evtx
    query: "evtx.event_id:22 AND (message:*.xyz* OR message:*.top* OR message:*.club* OR message:*.work* OR message:*.click*)"
    threshold: 5

  - name: File Hash Match Known Malware
    description: >-
      A file was created with a hash matching known malware (Sysmon Event ID 11).
      Requires hash blocklist integration.
    artifact_type: evtx
    query: "evtx.event_id:11 AND message:*Hash=*"
    threshold: 1
```

### 16. Browser Forensics Rules (NEW CATEGORY)

**File:** `16_browser_forensics.yaml`

```yaml
category: Browser Forensics
rules:
  - name: Browser Extension Installed
    description: >-
      A new browser extension was installed.
      Malicious extensions can steal data and monitor activity.
    artifact_type: hindsight
    query: "hindsight.record_type:extension AND hindsight.extension.event:install"
    threshold: 1

  - name: Download from Unusual Domain
    description: >-
      A file was downloaded from a suspicious or rare domain.
      May indicate malware delivery or phishing site.
    artifact_type: hindsight
    query: "hindsight.record_type:download AND NOT (hindsight.download.host:*google* OR hindsight.download.host:*microsoft* OR hindsight.download.host:*github*)"
    threshold: 1

  - name: InPrivate/Incognito Mode Usage
    description: >-
      Browser was used in private browsing mode.
      Attackers use private mode to avoid leaving traces.
    artifact_type: hindsight
    query: "hindsight.record_type:startup AND (hindsight.browser.mode:incognito OR hindsight.browser.mode:private)"
    threshold: 1

  - name: Credential Form Submission to Rare Domain
    description: >-
      A login form was submitted to an uncommon domain.
      May indicate credential phishing attack.
    artifact_type: hindsight
    query: "hindsight.record_type:form_and_field_data AND hindsight.form.action:submit AND NOT (hindsight.form.domain:*google* OR hindsight.form.domain:*microsoft* OR hindsight.form.domain:*facebook*)"
    threshold: 1

  - name: Multiple Failed Login Attempts
    description: >-
      Multiple failed form submissions detected.
      May indicate brute force attack or credential stuffing.
    artifact_type: hindsight
    query: "hindsight.record_type:form_and_field_data AND hindsight.form.result:failure"
    threshold: 5

  - name: Browser Visited Known Malicious Domain
    description: >-
      Browser accessed a domain flagged as malicious.
      Indicates potential drive-by download or phishing.
    artifact_type: hindsight
    query: "hindsight.record_type:visit AND (hindsight.visit.domain:*malware* OR hindsight.visit.domain:*phishing* OR hindsight.visit.domain:*evil*)"
    threshold: 1
```

### 17. Registry Analysis Rules (NEW CATEGORY)

**File:** `17_registry_forensics.yaml`

```yaml
category: Registry Forensics
rules:
  - name: Shim Database Created
    description: >-
      A shim database was registered.
      Attackers use application shimming for persistence and privilege escalation.
    artifact_type: registry
    query: "registry.key:*\\\\AppPatch\\\\Custom*"
    threshold: 1

  - name: Sticky Keys Backdoor
    description: >-
      Sticky Keys or other accessibility executables were modified.
      Common backdoor technique for persistence.
    artifact_type: registry
    query: "registry.key:*\\\\Image File Execution Options* AND (registry.value:*sethc* OR registry.value:*utilman* OR registry.value:*osk* OR registry.value:*magnify*)"
    threshold: 1

  - name: Winlogon Helper Modified
    description: >-
      Winlogon notification packages were changed.
      Used for persistence and credential theft.
    artifact_type: registry
    query: "registry.key:*\\\\Winlogon* AND (registry.value:*GPExtensions* OR registry.value:*Task* OR registry.value:*System*)"
    threshold: 1

  - name: LSA Security Package Modified
    description: >-
      LSA security packages were changed.
      Attackers add custom packages for credential theft.
    artifact_type: registry
    query: "registry.key:*\\\\LSA* AND (registry.value:*Security Packages* OR registry.value:*Authentication Packages*)"
    threshold: 1

  - name: COM Hijacking
    description: >-
      COM object handlers were modified.
      Used for privilege escalation and persistence.
    artifact_type: registry
    query: "registry.key:*\\\\CLSID*\\\\InProcServer32* AND NOT registry.value:*System32*"
    threshold: 1

  - name: Silent Process Exit Monitoring
    description: >-
      Silent Process Exit monitoring was configured.
      Used for persistence and process surveillance.
    artifact_type: registry
    query: "registry.key:*\\\\SilentProcessExit*"
    threshold: 1
```

### 18. Prefetch Analysis Rules (NEW CATEGORY)

**File:** `18_prefetch_analysis.yaml`

```yaml
category: Prefetch Analysis
rules:
  - name: Rare Executable Run
    description: >-
      An executable with no prefetch history was run.
      Could indicate new malware or first-time execution.
    artifact_type: prefetch
    query: "prefetch.run_count:1"
    threshold: 1

  - name: Executable Run from Temp Directory
    description: >-
      A program was executed from a temporary directory.
      Malware often runs from temp to avoid detection.
    artifact_type: prefetch
    query: "prefetch.path:*\\\\TEMP\\\\* OR prefetch.path:*\\\\AppData\\\\Local\\\\Temp\\\\*"
    threshold: 1

  - name: LOLBin Execution
    description: >-
      A living-off-the-land binary was executed.
      These tools are used for fileless attacks.
    artifact_type: prefetch
    query: "(prefetch.name:POWERSHELL* OR prefetch.name:WMIC* OR prefetch.name:RUNDLL32* OR prefetch.name:REGSVR32* OR prefetch.name:MSHTA* OR prefetch.name:CERTUTIL* OR prefetch.name:BITSADMIN*)"
    threshold: 1

  - name: Multiple Executables with Similar Names
    description: >-
      Multiple versions of similarly named executables were run.
      May indicate malware variants or updates.
    artifact_type: prefetch
    query: "prefetch.name:*update* OR prefetch.name:*setup* OR prefetch.name:*install*"
    threshold: 3

  - name: Executable with Long Runtime
    description: >-
      A process ran for an unusually long time.
      Could indicate mining, C2, or persistent backdoor.
    artifact_type: prefetch
    query: "prefetch.last_run:* AND prefetch.run_count:>10"
    threshold: 1
```

### 19. LNK File Analysis Rules (NEW CATEGORY)

**File:** `19_lnk_analysis.yaml`

```yaml
category: LNK File Analysis
rules:
  - name: LNK File in Unusual Location
    description: >-
      A shortcut file was found in a non-standard directory.
      LNK files in temp or user directories may indicate malware.
    artifact_type: lnk
    query: "lnk.path:*\\\\Temp\\\\* OR lnk.path:*\\\\AppData\\\\* OR lnk.path:*\\\\Public\\\\*"
    threshold: 1

  - name: LNK Targeting Script File
    description: >-
      A shortcut points to a script file (PS1, VBS, BAT, CMD).
      Common technique for executing malicious scripts.
    artifact_type: lnk
    query: "lnk.target:*\\\\*.ps1* OR lnk.target:*\\\\*.vbs* OR lnk.target:*\\\\*.bat* OR lnk.target:*\\\\*.cmd*"
    threshold: 1

  - name: LNK with Hidden Window
    description: >-
      A shortcut was configured to run with a hidden window.
      Used to execute malware without user awareness.
    artifact_type: lnk
    query: "lnk.show_command:SW_SHOWMINNOACTIVE OR lnk.show_command:SW_HIDE"
    threshold: 1

  - name: LNK Targeting Remote Path
    description: >-
      A shortcut points to a UNC path or remote location.
      May indicate lateral movement or payload staging.
    artifact_type: lnk
    query: "lnk.target:*\\\\\\\\*\\\\* OR lnk.target:*\\\\\\\\*\\\$*"
    threshold: 1

  - name: Multiple LNK Files Created Rapidly
    description: >-
      Multiple shortcut files were created in a short time.
      Could indicate worm propagation or mass infection.
    artifact_type: lnk
    query: "lnk.created:*"
    threshold: 10
```

### 20. MFT Analysis Rules (NEW CATEGORY)

**File:** `20_mft_analysis.yaml`

```yaml
category: MFT Analysis
rules:
  - name: File Created in System Directory
    description: >-
      A file was created in a protected Windows directory.
      Malware often drops files in system locations.
    artifact_type: mft
    query: "mft.full_path:*\\\\Windows\\\\* OR mft.full_path:*\\\\Program Files\\\\*"
    threshold: 1

  - name: File with Multiple Names (ADS)
    description: >-
      A file has multiple names or alternate data streams.
      Used by malware to hide payloads.
    artifact_type: mft
    query: "mft.file_name_attributes:*multiple* OR mft.ads_count:>1"
    threshold: 1

  - name: File Created and Deleted Rapidly
    description: >-
      A file was created and deleted within seconds.
      Indicates temporary payload execution or staging.
    artifact_type: mft
    query: "mft.crtime:* AND mft.mtime:* AND (mft.sequence_number:* OR mft.fn_deleted:*)"
    threshold: 5

  - name: File with Suspicious Extension
    description: >-
      A file with an extension commonly associated with malware.
      Includes script, executable, and archive extensions.
    artifact_type: mft
    query: "(mft.name:*.exe* OR mft.name:*.dll* OR mft.name:*.ps1* OR mft.name:*.vbs* OR mft.name:*.js* OR mft.name:*.hta*)"
    threshold: 1

  - name: File Timestamp Anomaly
    description: >-
      File timestamps are inconsistent or timestomped.
      Attackers modify timestamps to evade detection.
    artifact_type: mft
    query: "mft.crtime:>mft.mtime OR mft.mtime:>mft.a_time"
    threshold: 1
```

### 21. Zeek/Bro Network Analysis (NEW CATEGORY)

**File:** `21_zeek_analysis.yaml`

```yaml
category: Zeek Network Analysis
rules:
  - name: DNS Query to Rare Domain
    description: >-
      A DNS query was made to a domain with an uncommon TLD.
      Malware often uses rare TLDs for C2.
    artifact_type: zeek
    query: "zeek.log_type:dns AND (zeek.dns.qname:*.xyz* OR zeek.dns.qname:*.top* OR zeek.dns.qname:*.club*)"
    threshold: 5

  - name: Long DNS Query
    description: >-
      A DNS query with an unusually long domain name.
      May indicate DNS tunneling or DGA.
    artifact_type: zeek
    query: "zeek.log_type:dns AND zeek.dns.qname_length:>50"
    threshold: 1

  - name: SSL Certificate with Self-Signed
    description: >-
      An SSL connection used a self-signed certificate.
      Common in malware C2 to avoid certificate costs.
    artifact_type: zeek
    query: "zeek.log_type:ssl AND zeek.ssl.cert_subject:*self* OR zeek.ssl.cert_issuer:*self*"
    threshold: 1

  - name: HTTP Download of Executable
    description: >-
      An executable file was downloaded over HTTP.
      May indicate malware delivery.
    artifact_type: zeek
    query: "zeek.log_type:http AND zeek.http.uri:*.exe* OR zeek.http.uri:*.dll*"
    threshold: 1

  - name: Connection to Non-Standard Port
    description: >-
      A connection was made to an unusual port.
      Malware often uses non-standard ports for C2.
    artifact_type: zeek
    query: "zeek.log_type:conn AND NOT (zeek.conn.dst_port:80 OR zeek.conn.dst_port:443 OR zeek.conn.dst_port:53 OR zeek.conn.dst_port:25)"
    threshold: 10

  - name: Beaconing Behavior
    description: >-
      Regular periodic connections to the same destination.
      Indicates potential C2 beaconing.
    artifact_type: zeek
    query: "zeek.log_type:conn AND zeek.conn.duration:>0"
    threshold: 20
```

### 22. Enhanced Authentication Rules (EXPANSION)

**File:** `02_authentication_expanded.yaml` (add to existing)

```yaml
category: Authentication
rules:
  - name: Kerberos Double-Hop Authentication
    description: >-
      A Kerberos ticket was requested with delegation.
      Can indicate pass-the-ticket or constrained delegation abuse.
    artifact_type: evtx
    query: "evtx.event_id:4672 AND message:*SeDelegateRemoteAccessPrivilege*"
    threshold: 1

  - name: Smart Card Logon from Unknown Workstation
    description: >-
      A smart card authentication from an unusual computer.
      May indicate stolen smart card or credential.
    artifact_type: evtx
    query: "evtx.event_id:4624 AND message:*LogonType:2* AND message:*SmartCard*"
    threshold: 1

  - name: WDigest Authentication Enabled
    description: >-
      WDigest authentication was used (clear-text passwords in memory).
      Attackers enable this for credential theft.
    artifact_type: evtx
    query: "evtx.event_id:4624 AND message:*WDigest*"
    threshold: 1

  - name: Network Logon with Blank Password
    description: >-
      A network logon succeeded with an empty password.
      Indicates weak security configuration.
    artifact_type: evtx
    query: "evtx.event_id:4624 AND message:*LogonType:3* AND message:*NULL SID*"
    threshold: 1

  - name: Service Account Used Interactively
    description: >-
      A service account logged on interactively.
      Service accounts should never have interactive sessions.
    artifact_type: evtx
    query: "evtx.event_id:4624 AND (message:*svc* OR message:*service* OR message:*gmsa*) AND (message:*LogonType:2* OR message:*LogonType:10*)"
    threshold: 1
```

### 23. PowerShell-Specific Rules (EXPANSION)

**File:** `05_execution_powershell.yaml` (add to existing)

```yaml
category: PowerShell Execution
rules:
  - name: PowerShell Downgraded to Version 2
    description: >-
      PowerShell version 2 was explicitly requested.
      Version 2 lacks security features and is used by malware.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*powershell* AND message:*-version 2*"
    threshold: 1

  - name: PowerShell Bypass Execution Policy
    description: >-
      PowerShell was launched with -ExecutionPolicy Bypass.
      Used to run scripts despite restrictive policies.
    artifact_type: evtx
    query: "evtx.event_id:4688 AND message:*powershell* AND message:*-ExecutionPolicy* AND (message:*Bypass* OR message:*Unrestricted*)"
    threshold: 1

  - name: PowerShell Download Cradle
    description: >-
      PowerShell downloaded and executed a script in one command.
      Common malware delivery technique.
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*IEX* OR message:*Invoke-Expression* OR message:*Invoke-WebRequest* OR message:*DownloadString*)"
    threshold: 1

  - name: PowerShell Reflection Usage
    description: >-
      PowerShell loaded a .NET assembly via reflection.
      Used by fileless malware to avoid writing to disk.
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*[Reflection.Assembly]* OR message:*LoadFromByteArray* OR message::*Assembly.Load*)"
    threshold: 1

  - name: PowerShell Web Request to IP Address
    description: >-
      PowerShell made a web request directly to an IP.
      Malware often uses IPs instead of domains to evade detection.
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*Invoke-WebRequest* OR message:*DownloadFile*) AND message:*http://[0-9]"
    threshold: 1

  - name: PowerShell Module Import from Remote Path
    description: >-
      PowerShell imported a module from a UNC path.
      May indicate lateral movement or payload staging.
    artifact_type: evtx
    query: "evtx.event_id:4104 AND (message:*Import-Module* OR message:*.psm1*) AND message:*\\\\\\\\*"
    threshold: 1
```

### 24. Container/Cloud Rules (NEW CATEGORY)

**File:** `24_container_cloud.yaml`

```yaml
category: Container & Cloud
rules:
  - name: Docker Container Started with Privileged Flag
    description: >-
      A Docker container was started with --privileged flag.
      Grants full host access and bypasses container isolation.
    artifact_type: syslog
    query: "syslog.message:*docker* AND syslog.message:*--privileged*"
    threshold: 1

  - name: Kubernetes Pod with Host Network
    description: >-
      A Kubernetes pod was created with hostNetwork: true.
      Allows pod to access host network interfaces.
    artifact_type: syslog
    query: "syslog.message:*kubernetes* AND syslog.message:*hostNetwork*"
    threshold: 1

  - name: AWS CLI Assume Role from Unusual IP
    description: >-
      AWS STS AssumeRole called from an unusual source IP.
      May indicate credential compromise or lateral movement.
    artifact_type: syslog
    query: "syslog.message:*aws* AND syslog.message:*sts:AssumeRole*"
    threshold: 1

  - name: Azure AD Privileged Role Assigned
    description: >-
      A privileged Azure AD role was assigned to a user.
      Review for unauthorized privilege escalation.
    artifact_type: syslog
    query: "syslog.message:*AzureAD* AND (syslog.message:*Global Administrator* OR syslog.message:*Privileged Role Administrator*)"
    threshold: 1

  - name: GCP Service Account Key Created
    description: >-
      A new service account key was generated.
      Keys can be exfiltrated for persistent access.
    artifact_type: syslog
    query: "syslog.message:*gcloud* AND syslog.message:*create-key*"
    threshold: 1

  - name: S3 Bucket Made Public
    description: >-
      An S3 bucket policy was changed to allow public access.
      May lead to data exposure or unauthorized access.
    artifact_type: syslog
    query: "syslog.message:*s3:PutBucketPolicy* OR syslog.message:*s3:PutBucketAcl*"
    threshold: 1
```

---

## 📋 Implementation Priority

### Immediate (Week 1-2)
1. **Initial Access** - Critical for detecting phishing and malware delivery
2. **Impact** - Essential for ransomware and destructive attack detection
3. **Enhanced Sysmon** - Leverages existing Sysmon telemetry

### Short-Term (Week 3-4)
4. **PowerShell Expansion** - High-value for detecting fileless attacks
5. **Enhanced Authentication** - Improves credential theft detection
6. **Browser Forensics** - Adds visibility into web-based attacks

### Medium-Term (Month 2)
7. **Registry Analysis** - Deep persistence detection
8. **Prefetch Analysis** - Historical execution evidence
9. **LNK Analysis** - Shortcut-based attacks
10. **MFT Analysis** - File system forensics

### Long-Term (Month 3+)
11. **Zeek Analysis** - Network behavioral detection
12. **Resource Development** - Threat intel integration
13. **Container/Cloud** - Modern infrastructure coverage

---

## 🔧 Technical Requirements

### New Parsers Needed
| Artifact Type | Parser Status | Effort |
|--------------|---------------|--------|
| Registry | ✅ Exists | Low |
| Prefetch | ✅ Exists | Low |
| LNK | ✅ Exists | Low |
| MFT | ✅ Exists | Medium |
| Hindsight (Browser) | ✅ Exists | Medium |
| Zeek | ❌ Not implemented | High |
| Sysmon (dedicated) | ⚠️ Via EVTX | Low |

### Elasticsearch Index Templates
Need to create templates for:
- `fo-case-{id}-registry`
- `fo-case-{id}-prefetch`
- `fo-case-{id}-lnk`
- `fo-case-{id}-mft`
- `fo-case-{id}-hindsight`
- `fo-case-{id}-zeek`

### Performance Considerations
- **Threshold tuning**: Some rules have high thresholds (10, 20, 50) to reduce noise
- **Artifact type filtering**: Rules specify artifact_type to limit query scope
- **Sample size**: All rules return max 5 sample events to reduce memory usage

---

## 📊 Metrics & Validation

### Rule Effectiveness Tracking
For each rule, track:
1. **True Positive Rate**: Matches confirmed as malicious
2. **False Positive Rate**: Matches confirmed as benign
3. **Coverage**: % of cases where rule fired
4. **Dwell Time**: Time between attack and rule firing

### Recommended KPIs
- **Mean Time to Detect (MTTD)**: Target < 1 hour for critical rules
- **Alert Volume**: < 100 alerts per analyst per day
- **Investigation Time**: < 15 minutes per alert triage
- **Rule Coverage**: > 90% of MITRE ATT&CK techniques covered

---

## 🎯 MITRE ATT&CK Coverage Map

| Tactic | Current Rules | Proposed Rules | Total | Coverage % |
|--------|--------------|----------------|-------|------------|
| Reconnaissance | 0 | 5 | 5 | 15% |
| Resource Development | 0 | 5 | 5 | 10% |
| Initial Access | 0 | 11 | 11 | 45% |
| Execution | 9 | 15 | 24 | 70% |
| Persistence | 7 | 13 | 20 | 65% |
| Privilege Escalation | 5 | 10 | 15 | 60% |
| Defense Evasion | 6 | 12 | 18 | 65% |
| Credential Access | 6 | 11 | 17 | 70% |
| Discovery | 5 | 10 | 15 | 55% |
| Lateral Movement | 5 | 8 | 13 | 60% |
| Collection | 0 | 0 | 0 | 0% |
| Command & Control | 6 | 12 | 18 | 65% |
| Exfiltration | 5 | 8 | 13 | 60% |
| Impact | 0 | 11 | 11 | 50% |
| **TOTAL** | **49** | **131** | **180** | **55%** |

---

## 🚀 Next Steps

1. **Create YAML files** for each new category
2. **Test rules** against sample datasets
3. **Tune thresholds** based on false positive rates
4. **Document** each rule with MITRE ATT&CK mappings
5. **Integrate** with threat intelligence feeds
6. **Automate** rule updates from Sigma HQ
7. **Create** alert response playbooks
8. **Implement** machine learning for anomaly detection

---

*Generated: 2026-03-27*
*Total Proposed Rules: 131 new detection rules across 13 categories*
# ForensicsOperator Comprehensive Audit Report

**Date:** March 27, 2026  
**Project Path:** `/Users/nbuisson/Tools/Custom_tools/forensicsOperator`

---

## EXECUTIVE SUMMARY

This audit examines the forensicsOperator codebase across 8 key areas: code cleanup, RBAC analysis, alert/detection rules, modules analysis, ingesters analysis, collector analysis, performance improvements, and Celery/Redis configuration.

**Key Findings:**
- 82 Python files analyzed across api/, processor/, collector/, plugins/, modules/
- 2 roles defined (admin, analyst) with basic RBAC implementation
- 18 plugins and 17+ modules supported
- Multiple security and performance improvements identified
- Several code quality issues requiring attention

---

## 1. CODE CLEANUP

### 1.1 Dead Code / Unused Imports

**File:** `api/routers/alert_rules.py:2`
```python
import json, uuid  # Line 2
```
**Issue:** `uuid` imported but never used in file. `json` used only for loads/dumps.
**Recommendation:** Remove `uuid` import, use `json` directly from standard library.

**File:** `api/routers/cti.py:330-370`
```python
import urllib.request  # Line 330
import urllib.error    # Line 331
```
**Issue:** Multiple inline imports scattered throughout function bodies (lines 330, 331, 369, 370).
**Recommendation:** Move all imports to top of file per PEP 8.

**File:** `api/routers/global_alert_rules.py:451`
```python
import re as _re  # Inside function
```
**Issue:** Inline import inside `_eval_condition()` function.
**Recommendation:** Move to top-level imports (already has `import re` at line 17).

### 1.2 Duplicate Functionality

**File:** `api/routers/alert_rules.py` vs `api/routers/global_alert_rules.py`

**Issue:** Two separate alert rule systems with overlapping functionality:
- `alert_rules.py`: Per-case rules (65 lines, simpler)
- `global_alert_rules.py`: Global library rules (737 lines, feature-rich)

**Problems:**
1. Different data models (AlertRuleIn defined in both files)
2. alert_rules.py lacks category, sigma_yaml fields
3. Duplicate Redis storage pattern with different key structures
4. No migration path from per-case to global rules

**Recommendation:** 
- Deprecate `alert_rules.py` endpoints
- Migrate existing per-case rules to global library with case metadata
- Update frontend to use only global rules API

### 1.3 Poorly Structured Functions

**File:** `processor/tasks/module_task.py:97-196`
```python
def _run_custom_module(...) -> list[dict]:
```
**Issues:**
- 99 lines of complex sandbox logic
- Hardcoded environment variable references (should be parameters)
- No type hints on nested functions
- Error handling mixes logging and exceptions

**Recommendation:** Extract into separate `sandbox.py` module with proper class structure.

**File:** `api/routers/llm_config.py:148-866`
```python
# Multiple LLM provider implementations
def _call_openai_compat(...)
def _call_anthropic(...)
def _call_ollama(...)
```
**Issues:**
- 718 lines in single file
- Repeated HTTP request patterns
- No abstract base class for providers
- Hardcoded prompts as string constants

**Recommendation:** 
- Create `llm/providers.py` with Provider base class
- Implement strategy pattern for different providers
- Move prompts to separate `llm/prompts.py`

### 1.4 Unused Variables/Files

**File:** `api/main.py:19`
```python
from auth.dependencies import get_current_user, require_admin, require_analyst_or_admin
```
**Issue:** `get_current_user` imported but never used directly in main.py (only passed to routers).

**File:** `processor/tasks/module_task.py:28`
```python
import struct  # Line 28
```
**Issue:** `struct` imported but grep shows zero usage in file.

**File:** `modules/` directory
```
total 0
drwxr-xr-x@  2 nbuisson  staff   64 19 mars  21:37 .
drwxr-xr-x@ 23 nbuisson  staff  736 27 mars  12:58 ..
```
**Issue:** Empty modules directory (custom modules stored in `/app/modules` volume at runtime).

### 1.5 TODO/FIXME Comments

**Finding:** No TODO/FIXME/XXX/HACK/BUG comments found in codebase.

**Concern:** This is unusual for a codebase of this size (82 Python files, ~15,000+ lines). Suggests either:
1. Technical debt not documented
2. Comments stripped during cleanup
3. Issues tracked externally only

**Recommendation:** Implement code review process that requires TODO comments for known issues.

---

## 2. RBAC ANALYSIS

### 2.1 Roles Defined

**File:** `api/auth/service.py:68`
```python
VALID_ROLES = ("admin", "analyst")
```

**Roles:**
1. **admin**: Full system access, user management, configuration
2. **analyst**: Case operations, search, analysis, no admin functions

### 2.2 Permission Matrix

| Permission | admin | analyst | Endpoint/Function |
|------------|-------|---------|-------------------|
| Create/read/update/delete cases | ✓ | ✓ | `api/routers/cases.py` |
| Ingest files | ✓ | ✓ | `api/routers/ingest.py` |
| Search events | ✓ | ✓ | `api/routers/search.py` |
| Run modules | ✓ | ✓ | `api/routers/modules.py` |
| View module runs | ✓ | ✓ | `api/routers/modules.py` |
| Export data | ✓ | ✓ | `api/routers/export.py` |
| Use collector | ✓ | ✓ | `api/routers/collector.py` |
| Use AI analysis | ✓ | ✓ | `api/routers/llm_config.py` (analyze endpoints) |
| Create alert rules | ✓ | ✓ | `api/routers/global_alert_rules.py` |
| **User management** | ✓ | ✗ | `api/routers/auth.py:130-189` |
| **LLM configuration** | ✓ | ✗ | `api/routers/llm_config.py:74-117` |
| **S3 integration** | ✓ | ✗ | `api/routers/s3_integration.py` |
| **Cuckoo config** | ✓ | ✗ | `api/routers/modules.py:398-439` |
| **Malwoverview config** | ✓ | ✗ | `api/routers/modules.py:448-479` |
| **Edit custom modules** | ✓ | ✗ | `api/routers/editor.py` |

### 2.3 Protected Endpoints

**File:** `api/main.py:108-139`

```python
_analyst_or_admin = [Depends(require_analyst_or_admin)]
_admin_only       = [Depends(require_admin)]

# Protected — analyst or admin
app.include_router(cases.router,              dependencies=_analyst_or_admin)
app.include_router(ingest.router,             dependencies=_analyst_or_admin)
app.include_router(jobs.router,               dependencies=_analyst_or_admin)
app.include_router(search.router,             dependencies=_analyst_or_admin)
app.include_router(plugins.router,            dependencies=_analyst_or_admin)
app.include_router(saved_searches.router,     dependencies=_analyst_or_admin)
app.include_router(alert_rules.router,        dependencies=_analyst_or_admin)
app.include_router(export.router,             dependencies=_analyst_or_admin)
app.include_router(modules.router,            dependencies=_analyst_or_admin)
app.include_router(collector.router,          dependencies=_analyst_or_admin)
app.include_router(editor.router,             dependencies=_analyst_or_admin)  # ISSUE!
app.include_router(cti.router,                dependencies=_analyst_or_admin)
app.include_router(global_alert_rules.router, dependencies=_analyst_or_admin)
app.include_router(llm_config.router,         dependencies=_analyst_or_admin)  # ISSUE!
app.include_router(s3_integration.router,     dependencies=_admin_only)
app.include_router(metrics.router,            dependencies=_analyst_or_admin)
```

### 2.4 RBAC Coverage Gaps

**CRITICAL ISSUE #1:** `editor.router` registered with `_analyst_or_admin` but contains admin-only functions.

**File:** `api/routers/editor.py`
```python
# Lines 140-160: Custom module editing
@router.put("/custom-modules/{module_id}")
def update_custom_module(...):  # Allows analysts to edit Python code!
    
@router.delete("/custom-modules/{module_id}")
def delete_custom_module(...):  # Allows analysts to delete modules!
```

**Risk:** Analysts can inject arbitrary Python code into custom modules, potentially:
- Exfiltrating MinIO credentials
- Modifying analysis results
- Creating backdoors

**Fix:** Add `require_admin` dependency to editor router or individual endpoints.

**CRITICAL ISSUE #2:** `llm_config.router` allows analysts to reach admin config endpoints.

**File:** `api/main.py:137`
```python
app.include_router(llm_config.router, dependencies=_analyst_or_admin)
```

**Problem:** While individual admin endpoints have `require_admin`, the router registration is inconsistent.

**Fix:** Register llm_config with `_admin_only` and create separate analyst-only routes for analysis endpoints.

### 2.5 Missing RBAC Features

1. **No case-level permissions**: All analysts can access all cases
   - **Recommendation:** Add `case_analysts` field to case metadata
   - Check permissions in `cases.py:get_case()` and search endpoints

2. **No audit logging**: User actions not tracked
   - **Recommendation:** Log all write operations (create/update/delete) with user ID
   - Store in separate Elasticsearch index `fo-audit-logs`

3. **No rate limiting**: Authentication endpoints vulnerable to brute force
   - **Recommendation:** Add rate limiting to `/auth/login` and `/auth/token`
   - Use Redis-based sliding window counter

4. **No API key support**: Only JWT tokens
   - **Recommendation:** Add service account API keys for automation
   - Keys stored in Redis with expiration and permissions

5. **No session management**: JWTs valid for 8 hours (configurable)
   - **Recommendation:** Implement token revocation list in Redis
   - Add logout endpoint to blacklist tokens

---

## 3. ALERT/DETECTION RULES ANALYSIS

### 3.1 Rule Storage

**File:** `api/routers/global_alert_rules.py:39-40`
```python
GLOBAL_KEY        = "fo:alert_rules:_global"
GLOBAL_SEEDED_KEY = "fo:alert_rules:_global:seeded"
```

**Storage:** Redis hash with JSON-serialized array
**Structure:**
```json
{
  "id": "a1b2c3d4",
  "name": "Suspicious PowerShell",
  "category": "Execution",
  "description": "...",
  "artifact_type": "evtx",
  "query": "evtx.event_id:4688 AND message:*powershell*",
  "threshold": 1,
  "created_at": "2026-03-27T10:00:00Z",
  "rule_type": "sigma",  // optional
  "sigma_yaml": "...",   // optional
  "sigma_id": "...",     // optional
  "sigma_level": "high", // optional
  "sigma_tags": [...],   // optional
  "sigma_status": "experimental" // optional
}
```

### 3.2 Rule Creation Flow

**Endpoints:**
1. `POST /alert-rules/library` - Manual creation
2. `POST /alert-rules/library/sigma` - Sigma YAML import
3. `POST /alert-rules/generate` - LLM-generated Sigma
4. `POST /alert-rules/sigma/parse` - Preview Sigma conversion

**Sigma Import Process** (`global_alert_rules.py:235-320`):
```
1. Parse Sigma YAML (lines 267-272)
2. Extract title, description, logsource, detection
3. Convert detection to ES query_string (lines 384-487)
4. Map logsource to artifact_type (lines 560-583)
5. Map tags to MITRE category (lines 537-558)
6. Store in Redis with metadata
```

### 3.3 Rule Evaluation

**File:** `api/routers/global_alert_rules.py:626-719`

**Endpoint:** `POST /cases/{case_id}/alert-rules/run-library`

**Process:**
```python
for rule in rules:
    index = f"fo-case-{case_id}-{artifact_type}" or f"fo-case-{case_id}-*"
    body = {
        "query": {
            "query_string": {
                "query": rule["query"],
                "default_operator": "AND"
            }
        },
        "size": 5,
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    resp = es_req("POST", f"/{index}/_search", body)
    count = resp["hits"]["total"]["value"]
    if count >= rule["threshold"]:
        matches.append({...})
```

**Issues:**

1. **No caching**: Rules re-evaluated on every request
   - **Impact:** High ES load with many rules
   - **Fix:** Cache results in Redis for 5 minutes with rule hash key

2. **No parallelization**: Sequential rule execution
   - **Impact:** Slow for 50+ rules
   - **Fix:** Use `asyncio.gather()` for concurrent ES queries

3. **Silent failures**: `except Exception: pass` (line 670)
   - **Impact:** Failed rules not reported
   - **Fix:** Log errors, return partial results with error metadata

4. **No timeout**: ES queries can hang indefinitely
   - **Fix:** Add `timeout=30s` to ES request

### 3.4 Default Rules

**File:** `api/alert_rules/*.yaml` (11 files)

**Categories:**
- `01_anti_forensics.yaml` - Anti-forensics detection
- `02_authentication.yaml` - Authentication anomalies
- `03_privilege_escalation.yaml` - Privilege escalation
- `04_persistence.yaml` - Persistence mechanisms
- `05_execution.yaml` - Execution techniques
- `06_lateral_movement.yaml` - Lateral movement
- `07_defense_evasion.yaml` - Defense evasion
- `08_credential_access.yaml` - Credential access
- `09_discovery.yaml` - Discovery activities
- `10_command_control.yaml` - C2 communication
- `11_exfiltration.yaml` - Exfiltration attempts

**Seeding Process** (`global_alert_rules.py:162-200`):
```python
@router.post("/alert-rules/library/seed")
def seed_library(replace: bool = False):
    # Loads YAML files on first access
    # Skips existing rules by name match
    # One-time seeding tracked by GLOBAL_SEEDED_KEY
```

**Issue:** Seeding happens on first Redis access, not at deployment.
**Risk:** Rules not available if Redis restarts before first access.
**Fix:** Seed rules at API startup in `main.py:_on_startup()`.

### 3.5 Integration with Elasticsearch Alerts

**Current State:** Alert rules are ES query_string queries executed on-demand.

**Missing Features:**
1. **No real-time alerting**: Rules only run when manually triggered
2. **No alert history**: Matches not persisted
3. **No alert correlation**: Related alerts not grouped
4. **No alert enrichment**: IOCs not cross-referenced with CTI

**Recommendations:**
1. Add Celery task for scheduled rule execution (every 5-15 minutes)
2. Store fired alerts in `fo-case-{case_id}-alerts` index
3. Implement alert correlation by host/user/time window
4. Cross-reference with CTI IOCs from `cti.py`

---

## 4. MODULES ANALYSIS

### 4.1 Supported Modules

**File:** `processor/tasks/module_task.py:5-18` (docstring)

**Built-in Modules (17):**
1. `hayabusa` - Sigma-based EVTX threat hunting
2. `strings` - Printable string extraction
3. `strings_analysis` - Categorized strings with IOC identification
4. `hindsight` - Browser forensics (Chrome/Firefox/Edge)
5. `regripper` - Windows registry analysis
6. `wintriage` - Windows triage collection analysis
7. `yara` - YARA rule scanning
8. `exiftool` - Metadata extraction
9. `volatility3` - Memory forensics
10. `oletools` - Office document macro analysis
11. `ole_analysis` - Alias for oletools
12. `pe_analysis` - PE executable inspection
13. `grep_search` - Regex-based pattern search
14. `malwoverview` - VirusTotal hash lookup
15. `access_log_analysis` - Web access log analysis
16. `cuckoo` - Cuckoo Sandbox integration
17. `de4dot` - .NET deobfuscation

**Module Registry:** `api/modules_registry/*.yaml`

### 4.2 Implementation Status

**Fully Implemented:**
- `hayabusa`: Lines 402-892 (490 lines) - Full CSV/JSONL parsing, ES indexing
- `strings`: Lines 894-940 (46 lines) - Basic strings extraction
- `regripper`: Lines 1057-1152 (95 lines) - Registry hive parsing
- `yara`: Lines 1897-2023 (126 lines) - Rule compilation and scanning
- `exiftool`: Lines 2025-2194 (169 lines) - Metadata extraction

**Partially Implemented:**
- `volatility3`: Lines 2390-2490 (100 lines)
  - **Issue:** Requires external Python script (`vol_plugin.py`)
  - **Gap:** No built-in volatility plugins, relies on user-provided scripts
  - **Line 2438:** `raise RuntimeError("No source files found for Volatility analysis.")` - Poor error handling

- `hindsight`: Lines 942-1055 (113 lines)
  - **Issue:** Depends on external hindsight binary
  - **Line 945:** Raises error if binary not found

**Stub/Wrapper Only:**
- `cuckoo`: Lines 3203-3378 (175 lines)
  - **Issue:** Only API client, no local analysis
  - **Dependency:** Requires external Cuckoo Sandbox instance
  - **Line 3203:** `def _run_cuckoo(...)` - Just forwards to Cuckoo API

- `malwoverview`: Lines 3549-3646 (97 lines)
  - **Issue:** Wrapper around malwoverview CLI or VT API
  - **Line 3549:** No local scanning capability

### 4.3 Module Execution Flow

**File:** `processor/tasks/module_task.py:247-371`

```python
@app.task(bind=True, name="module.run", queue="modules")
def run_module(self, run_id, case_id, module_id, source_files, params=None):
    # 1. Download source files from MinIO (lines 276-283)
    for sf in source_files:
        minio.fget_object(BUCKET, sf["minio_key"], dest)
    
    # 2. Run module (lines 287-311)
    RUNNERS = {
        "hayabusa": _run_hayabusa,
        "yara": _run_yara,
        # ...
    }
    runner = RUNNERS.get(module_id)
    if runner:
        results = runner(run_id, work_dir, sources_dir, params, tool_meta)
    else:
        results = _run_custom_module(...)  # Custom Python module
    
    # 3. Upload results to MinIO (lines 330-335)
    minio.fput_object(BUCKET, output_key, results_json)
    
    # 4. Update Redis with status (lines 337-359)
    _update(r, run_id, status="COMPLETED", total_hits=len(results), ...)
```

### 4.4 Error Handling Gaps

**Issue #1:** No retry logic for MinIO operations in module_task.py

**File:** `processor/tasks/module_task.py:276-283`
```python
for sf in source_files:
    dest = sources_dir / sf["filename"]
    minio.fget_object(MINIO_BUCKET, k, str(d))  # No retry!
```

**Contrast:** `ingest_task.py` uses `_minio_op()` with exponential backoff (lines 216-234).

**Fix:** Apply `_minio_op()` wrapper to all MinIO operations in module_task.py.

**Issue #2:** Silent ES indexing failures

**File:** `processor/tasks/module_task.py:317-324`
```python
try:
    indexed = _hayabusa_index_to_es(case_id, run_id, results, ingested_at)
    tool_meta["log"] += f"\nIndexed {indexed} events..."
except Exception as _es_exc:
    logger.warning("[%s] ES indexing failed (non-fatal): %s", run_id, _es_exc)
    tool_meta["log"] += f"\n[ES index warning: {_es_exc}]\n"
```

**Problem:** ES failures treated as non-fatal, no retry, no user notification.

**Fix:** 
- Retry ES indexing 3 times with backoff
- Update run status to "COMPLETED_WITH_ERRORS" if ES fails
- Surface error in UI via `tool_meta["log"]`

**Issue #3:** No validation of module parameters

**File:** `processor/tasks/module_task.py:251`
```python
params: dict | None = None,
```

**Problem:** User-provided params passed directly to modules without validation.

**Risk:** 
- Path traversal via file paths in params
- Command injection if params used in shell commands
- Resource exhaustion via large values

**Fix:** 
- Define param schemas per module
- Validate params before passing to runners
- Sanitize file paths and command arguments

### 4.5 Module Execution Issues

**Issue:** Hardcoded resource limits

**File:** `processor/tasks/module_task.py:89-94`
```python
_SANDBOX_CPU_SECONDS  = int(os.getenv("SANDBOX_CPU_SECONDS", "3600"))
_SANDBOX_MEMORY_BYTES = int(os.getenv("SANDBOX_MEMORY_BYTES", str(2 * 1024**3)))
_SANDBOX_FSIZE_BYTES  = int(os.getenv("SANDBOX_FSIZE_BYTES", str(500 * 1024**2)))
_SANDBOX_NPROC        = int(os.getenv("SANDBOX_NPROC", "64"))
_SANDBOX_TIMEOUT      = int(os.getenv("SANDBOX_TIMEOUT_SEC", "1800"))
```

**Problem:** All modules share same limits, but:
- Hayabusa may need 2+ hours for large EVTX sets
- Volatility needs 8+ GB RAM for large memory dumps
- YARA scanning can spawn 100s of threads

**Fix:** 
- Per-module resource profiles in YAML registry
- Allow users to override limits at run creation (with caps)

---

## 5. INGESTERS ANALYSIS

### 5.1 File Upload Flow

**File:** `api/routers/ingest.py:198-278`

```python
@router.post("/cases/{case_id}/ingest")
async def ingest_files(case_id, files: List[UploadFile], background_tasks):
    # 1. Stream upload to local temp file (lines 227-250)
    tmp_fd, tmp_path = tempfile.mkstemp(...)
    with open(tmp_path, "wb") as out:
        while True:
            chunk = await upload.read(4 MB)  # Async chunks
            out.write(chunk)
    
    # 2. Handle ZIP extraction (lines 252-254)
    if filename.endswith(".zip"):
        _handle_zip_async(...)
    else:
        _ingest_one_async(...)
    
    # 3. Background upload to MinIO (line 256)
    background_tasks.add_task(_bg_upload_and_dispatch, ...)
```

**Flow Diagram:**
```
Client Upload → Temp File → BackgroundTask → MinIO → Redis Job Status → Celery Task → ES Index
     ↓                                                              ↓
  HTTP 200                                                      Celery Queue
 (Job IDs)
```

### 5.2 Plugin Detection and Execution

**File:** `processor/tasks/ingest_task.py:58-167`

```python
@app.task(bind=True, name="ingest.process_artifact", queue="ingest")
def process_artifact(self, job_id, case_id, minio_object_key, original_filename):
    # 1. Download from MinIO (lines 88-92)
    minio.fget_object(BUCKET, minio_object_key, local_file)
    
    # 2. Detect MIME type (line 97)
    mime_type = detect_mime(local_file)
    
    # 3. Find matching plugin (line 102)
    plugin_class = _plugin_loader.get_plugin(local_file, mime_type)
    
    # 4. Run plugin (lines 108-120)
    plugin = plugin_class(ctx)
    for raw_event in plugin.parse():
        event = _merge_base_fields(raw_event, ...)
        batch.append(event)
        if len(batch) >= BULK_SIZE:
            indexer.bulk_index(case_id, batch)
    
    # 5. Mark complete (lines 145-156)
    update_job_status(r, job_id, status="COMPLETED", ...)
```

### 5.3 ES Indexing Flow

**File:** `processor/utils/es_bulk.py:18-66`

```python
class ESBulkIndexer:
    def bulk_index(self, case_id, events):
        # 1. Build NDJSON body (lines 27-35)
        for event in events:
            index = f"fo-case-{case_id}-{artifact_type}"
            action = {"index": {"_index": index, "_id": fo_id}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))
        
        # 2. POST to ES (lines 37-48)
        req = urllib.request.Request(f"{es_url}/_bulk", ...)
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                logger.error("Bulk indexing had %d errors", len(error_items))
```

**Issue:** No retry logic for ES bulk indexing.

**Fix:** Implement exponential backoff for ES failures (similar to MinIO retry).

### 5.4 Bottlenecks and Issues

**Issue #1:** Single-threaded plugin parsing

**File:** `processor/tasks/ingest_task.py:113-120`
```python
for raw_event in plugin.parse():
    event = _merge_base_fields(raw_event, ...)
    batch.append(event)
    if len(batch) >= BULK_SIZE:
        indexer.bulk_index(case_id, batch)
```

**Problem:** Plugin parsing and ES indexing happen in same thread. Slow plugins block indexing.

**Fix:** Use producer-consumer pattern:
- Producer thread: Parse plugin, yield events to queue
- Consumer thread: Batch events, bulk index to ES

**Issue #2:** No backpressure control

**File:** `processor/tasks/ingest_task.py:113-120`
```python
for raw_event in plugin.parse():
    batch.append(event)  # Unbounded list growth!
```

**Problem:** If ES is slow, batch list grows indefinitely, potentially OOM.

**Fix:** 
- Use bounded queue (max 10,000 events)
- Block plugin parsing if queue full
- Add memory monitoring

**Issue #3:** No progress tracking during parsing

**File:** `processor/tasks/ingest_task.py:113-120`
```python
# No progress updates during plugin.parse() loop
```

**Problem:** Large files (10M+ events) show no progress for hours.

**Fix:** 
- Update Redis every 10,000 events
- Show `progress_pct` in job status

**Issue #4:** ZIP extraction loads all files into memory

**File:** `api/routers/ingest.py:129-195`
```python
def _handle_zip_async(...):
    with zf:
        for entry in zf.namelist():
            with zf.open(entry) as src, open(extracted_path, "wb") as dst:
                shutil.copyfileobj(src, dst)  # Extracts all at once
```

**Problem:** Large ZIP files (10+ GB) exhaust disk space in temp directory.

**Fix:** 
- Stream ZIP members directly to MinIO without temp extraction
- Add size validation before extraction
- Support ZIP64 format

---

## 6. COLLECTOR ANALYSIS

### 6.1 Data Collection Overview

**File:** `collector/collect.py:1-1028`

**Purpose:** Live artifact collection from Windows/Linux/macOS systems.

**Supported Artifacts:**

**Windows:**
- EVTX event logs (Security, System, PowerShell, Sysmon, etc.)
- Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
- Prefetch files (.pf)
- LNK files and RecentItems
- Browser artifacts (Chrome, Firefox, Edge, Opera, Vivaldi)
- Scheduled tasks
- Memory dump (via winpmem)

**Linux:**
- System logs (/var/log/*, journalctl)
- Shell histories (.bash_history, .zsh_history)
- System config (/etc/passwd, /etc/shadow, etc.)
- Cron jobs
- SSH artifacts
- PCAP files
- Suricata/Zeek logs
- Memory dump (via avml, fmem)

**macOS:**
- Unified logs (log show)
- Shell histories
- LaunchAgents/LaunchDaemons
- Browser artifacts (Safari, Chrome, Firefox)
- System triage commands
- Memory dump (via osxpmem)

### 6.2 Collection Flow

**File:** `collector/collect.py:88-178`

```python
class Collector:
    def __init__(self, output, collect, verbose, dry_run):
        self.staging = Path(tempfile.mkdtemp(prefix="fo_collect_"))
        self._items: list[tuple[str, Path]] = []
    
    def _add(self, src, arcname):
        # Add file to archive list
        self._items.append((arcname, src))
    
    def collect_all(self):
        # Platform-specific collection
        self._evtx()
        self._registry()
        ...
    
    def package(self):
        with zipfile.ZipFile(output, "w", ZIP_DEFLATED) as zf:
            for arcname, path in self._items:
                zf.write(str(path), arcname)
```

### 6.3 Integration Points

**Upload to ForensicsOperator:**

**File:** `collector/collect.py:898-940`
```python
def upload_to_fo(zip_path, api_url, case_id, api_token):
    url = f"{api_url.rstrip('/')}/cases/{case_id}/ingest"
    # Multipart form upload
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=600) as resp:
        print(f"[+] Upload successful (HTTP {resp.status})")
```

**Integration Issues:**

1. **No retry on upload failure**
   - **Line 920-938:** Single upload attempt
   - **Fix:** Retry 3 times with exponential backoff

2. **No integrity check**
   - **Issue:** No SHA256 hash verification after upload
   - **Fix:** Calculate hash before upload, verify after

3. **No progress reporting**
   - **Issue:** Large uploads (10+ GB) show no progress
   - **Fix:** Use `tqdm` or custom progress callback

### 6.4 Missing Features

1. **No artifact filtering by date range**
   - **Issue:** Collects all EVTX logs, even if only last 7 days needed
   - **Fix:** Add `--from-date` and `--to-date` options

2. **No compression level control**
   - **Line 167:** `ZIP_DEFLATED, compresslevel=6`
   - **Fix:** Add `--compression-level` option (1-9)

3. **No parallel collection**
   - **Issue:** Artifacts collected sequentially
   - **Fix:** Use ThreadPoolExecutor for independent collections

4. **No exclusion patterns**
   - **Issue:** Cannot exclude specific files/directories
   - **Fix:** Add `--exclude` glob patterns

5. **No post-collection validation**
   - **Issue:** Doesn't verify ZIP integrity before upload
   - **Fix:** Test ZIP file after packaging

### 6.5 Security Issues

**Issue #1:** Memory dumps stored unencrypted

**File:** `collector/collect.py:367-423`
```python
def _memory(self):
    dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.dmp"
    # Dump written to disk, added to ZIP
```

**Risk:** Memory dumps contain sensitive data (passwords, keys).

**Fix:** 
- Encrypt memory dumps with AES-256
- Add `--encrypt-memory` option with passphrase

**Issue #2:** No secure deletion of temp files

**File:** `collector/collect.py:175-178`
```python
def cleanup(self):
    shutil.rmtree(self.staging, ignore_errors=True)
```

**Risk:** Sensitive artifacts recoverable from disk.

**Fix:** Use `shred` or secure deletion library.

---

## 7. PERFORMANCE IMPROVEMENTS

### 7.1 Celery Configuration Issues

**File:** `processor/celery_app.py:1-73`

**Current Configuration:**
```python
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=3600,
    task_time_limit=7200,
    result_expires=604800,
    worker_max_tasks_per_child=50,
    broker_transport_options={
        "visibility_timeout": 7200,
        "socket_keepalive": True,
        "retry_policy": {"timeout": 5.0},
    },
)
```

**Issues:**

1. **No task priorities**
   - **Problem:** All tasks treated equally
   - **Impact:** Critical analyses blocked by low-priority tasks
   - **Fix:** Add priority queue (0-9) with Celery priorities

2. **Single result backend**
   - **Line 18:** `backend=REDIS_URL`
   - **Problem:** Redis used for both broker and backend
   - **Impact:** Task results compete with task messages
   - **Fix:** Use separate Redis DB or database for results

3. **No rate limiting per task**
   - **Problem:** Can dispatch unlimited module runs
   - **Impact:** Resource exhaustion
   - **Fix:** Add `task_rate_limit` per task type

4. **Fixed prefetch multiplier**
   - **Line 44:** `worker_prefetch_multiplier=1`
   - **Problem:** Workers fetch only 1 task at a time
   - **Impact:** Low utilization for I/O-bound tasks
   - **Fix:** 
     - ingest queue: multiplier=4 (I/O-bound)
     - modules queue: multiplier=1 (CPU-bound)

### 7.2 Redis Usage Patterns

**Current Usage:**
- Task broker (Celery)
- Result backend (Celery)
- Job status storage (`job:{job_id}`)
- Module run storage (`fo:module_run:{run_id}`)
- Alert rules (`fo:alert_rules:_global`)
- LLM config (`fo:llm_config`)
- User auth (`fo:user:{username}`)

**Issues:**

1. **No key expiration strategy**
   - **Problem:** Old job/module run keys persist indefinitely
   - **Fix:** Set TTL based on retention policy (7 days)

2. **No Redis clustering**
   - **Problem:** Single Redis instance = single point of failure
   - **Fix:** Deploy Redis Sentinel or cluster

3. **No connection pooling in API**
   - **File:** `api/auth/service.py:22-24`
   ```python
   def _redis():
       return redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)
   ```
   - **Problem:** New connection per request
   - **Fix:** Use `ConnectionPool` singleton

4. **No Redis persistence configuration**
   - **Problem:** RDB/AOF not configured
   - **Impact:** Data loss on Redis restart
   - **Fix:** Enable AOF with `appendfsync=everysec`

### 7.3 Elasticsearch Bulk Indexing

**Current Implementation:**

**File:** `processor/utils/es_bulk.py:37-48`
```python
req = urllib.request.Request(url, data=body.encode(), ...)
with urllib.request.urlopen(req, timeout=60) as resp:
    result = json.loads(resp.read())
```

**Issues:**

1. **No HTTP connection reuse**
   - **Problem:** New TCP connection per bulk request
   - **Impact:** High latency, port exhaustion
   - **Fix:** Use `urllib3.PoolManager` or `requests.Session`

2. **No bulk size tuning**
   - **File:** `ingest_task.py:31`
   ```python
   BULK_SIZE = int(os.getenv("BULK_SIZE", "500"))
   ```
   - **Problem:** Fixed 500 events regardless of event size
   - **Fix:** Dynamic bulk size based on total bytes (target 5-10 MB)

3. **No parallel indexing**
   - **Problem:** Single-threaded indexing per job
   - **Fix:** Index multiple artifact types in parallel threads

4. **No ES node discovery**
   - **Problem:** Single ES URL hardcoded
   - **Fix:** Use ES sniffing for cluster discovery

### 7.4 Memory/CPU Optimization

**Issue #1:** No streaming for large file parsing

**File:** `processor/tasks/module_task.py:501-587`
```python
def _parse_hayabusa_csv(path, tool_meta):
    with open(path, "r") as fh:
        reader = csv.DictReader(fh)
        for lineno, row in enumerate(reader, 2):  # Loads all into memory
            results.append({...})  # List grows indefinitely
```

**Problem:** Large Hayabusa output (10M+ rows) causes OOM.

**Fix:** 
- Stream results to ES in batches
- Don't accumulate all results in memory
- Use generator pattern

**Issue #2:** No CPU affinity control

**Problem:** Celery workers not pinned to CPU cores.

**Fix:** 
- Use `taskset` or `os.sched_setaffinity()`
- Pin workers to specific cores

**Issue #3:** No memory monitoring

**Problem:** Workers don't track memory usage.

**Fix:** 
- Add memory profiling decorator
- Kill workers exceeding memory limit

### 7.5 Caching Opportunities

**1. Elasticsearch Query Results**

**File:** `api/services/elasticsearch.py:101-170`
```python
def search_events(case_id, query, artifact_type, ...):
    # No caching!
    result = _request("POST", f"/{index}/_search", body)
```

**Fix:** Cache search results in Redis for 5 minutes:
```python
cache_key = f"es:search:{case_id}:{query_hash}"
cached = redis.get(cache_key)
if cached:
    return json.loads(cached)
result = _request(...)
redis.setex(cache_key, 300, json.dumps(result))
```

**2. Plugin Loading**

**File:** `processor/plugin_loader.py:30-79`
```python
def load(self):
    # Scans plugins directory every time
    for plugin_file in self.plugins_dir.rglob("*_plugin.py"):
        self._load_module(plugin_file)
```

**Fix:** Cache plugin list in Redis with file modification time check.

**3. Module Registry**

**File:** `api/routers/modules.py:106-110`
```python
_MODULES_CACHE: list[dict] | None = None

def _get_modules():
    global _MODULES_CACHE
    if _MODULES_CACHE is None:
        _MODULES_CACHE = _load_modules_from_registry()
    return _MODULES_CACHE
```

**Issue:** Cache invalidated on every pod restart.

**Fix:** Cache in Redis with TTL, invalidate on YAML change.

### 7.6 Connection Pooling

**Missing Connection Pools:**

1. **Elasticsearch:** No pooling, new connection per request
2. **MinIO:** Client instantiated per task
3. **Redis:** New connection per API request

**Recommendations:**

**Elasticsearch Pool:**
```python
# api/services/elasticsearch.py
_es_pool = urllib3.PoolManager(
    maxsize=20,
    block=True,
    timeout=30
)

def _request(method, path, body=None):
    resp = _es_pool.request(method, f"{ES_URL}{path}", ...)
```

**MinIO Pool:**
```python
# processor/tasks/ingest_task.py
_minio_client = None

def get_minio():
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(...)
    return _minio_client
```

**Redis Pool:**
```python
# api/config.py
_redis_pool = redis.ConnectionPool.from_url(settings.REDIS_URL)

def get_redis():
    return redis.Redis(connection_pool=_redis_pool)
```

---

## 8. CELERY/REDIS ISSUES

### 8.1 Task Routing Configuration

**File:** `processor/celery_app.py:46-59`
```python
task_queues=(
    Queue("ingest",  _default_exchange, routing_key="ingest"),
    Queue("modules", _default_exchange, routing_key="modules"),
    Queue("default", _default_exchange, routing_key="default"),
),
task_routes={
    "ingest.*": {"queue": "ingest",  "routing_key": "ingest"},
    "module.*": {"queue": "modules", "routing_key": "modules"},
},
```

**Issues:**

1. **No dead letter queue**
   - **Problem:** Failed tasks lost after max retries
   - **Fix:** Add DLQ for failed tasks:
   ```python
   Queue("ingest_dlq", _default_exchange, routing_key="ingest_dlq")
   ```

2. **No priority queues**
   - **Problem:** All tasks same priority
   - **Fix:** Add priority parameter to queues

3. **No queue-specific TTL**
   - **Problem:** Tasks can wait indefinitely
   - **Fix:** Add `queue_message_ttl` per queue

### 8.2 Queue Configuration

**Current Queues:**
- `ingest`: I/O-bound file parsing
- `modules`: CPU-bound analysis
- `default`: Fallback

**Missing Queues:**

1. **`alerts`**: Scheduled alert rule evaluation
2. **`cti`**: CTI feed polling and IOC matching
3. **`exports`**: Large CSV/PDF exports
4. **`cleanup`**: Index cleanup, temp file deletion

**Recommendation:**
```python
task_queues=(
    Queue("ingest",   routing_key="ingest",   consumer_timeout=300),
    Queue("modules",  routing_key="modules",  consumer_timeout=600),
    Queue("alerts",   routing_key="alerts",   consumer_timeout=120),
    Queue("cti",      routing_key="cti",      consumer_timeout=120),
    Queue("exports",  routing_key="exports",  consumer_timeout=600),
    Queue("cleanup",  routing_key="cleanup",  consumer_timeout=300),
    Queue("default",  routing_key="default"),
)
```

### 8.3 Result Backend Usage

**File:** `processor/celery_app.py:18`
```python
app = Celery(
    "forensics_processor",
    broker=REDIS_URL,
    backend=REDIS_URL,  # Same Redis for broker and backend
)
```

**Issues:**

1. **No result expiration tuning**
   - **Line 38:** `result_expires=604800` (7 days)
   - **Problem:** All results expire at same time
   - **Fix:** Per-task expiration

2. **No result compression**
   - **Problem:** Large results (module outputs) stored uncompressed
   - **Fix:** Enable result compression:
   ```python
   result_compression="gzip"
   ```

3. **No result persistence**
   - **Problem:** Results lost on Redis restart
   - **Fix:** Enable Redis AOF or use database backend

### 8.4 Misconfigurations

**Issue #1:** Visibility timeout too short

**File:** `processor/celery_app.py:65`
```python
broker_transport_options={
    "visibility_timeout": 7200,  # 2 hours
}
```

**Problem:** Module tasks can run up to 2 hours (line 38: `task_time_limit=7200`).

**Risk:** Task re-queued while still running if visibility timeout < task duration.

**Fix:** 
```python
"visibility_timeout": 14400,  # 4 hours (2x max task time)
```

**Issue #2:** No broker heartbeat

**Problem:** No heartbeat configuration for Redis broker.

**Fix:**
```python
broker_heartbeat=30,
broker_heartbeat_checkrate=3.0,
```

**Issue #3:** No task serialization security

**File:** `processor/celery_app.py:23-25`
```python
task_serializer="json",
accept_content=["json"],
```

**Problem:** No content-type validation.

**Fix:**
```python
accept_content=["json"],
task_serializer="json",
result_serializer="json",
event_serializer="json",
accept_magic_key=False,
```

---

## SUMMARY OF CRITICAL FINDINGS

### Security Issues (Critical)

1. **RBAC bypass in editor router** (`api/main.py:128`)
   - Analysts can edit/delete custom Python modules
   - **Fix:** Add `require_admin` dependency

2. **No input validation for module parameters** (`processor/tasks/module_task.py:251`)
   - Risk of command injection, path traversal
   - **Fix:** Validate and sanitize all params

3. **Memory dumps stored unencrypted** (`collector/collect.py:367-423`)
   - Sensitive data exposure
   - **Fix:** Encrypt with AES-256

4. **No rate limiting on auth endpoints** (`api/routers/auth.py:63-97`)
   - Brute force vulnerability
   - **Fix:** Add Redis-based rate limiting

### Performance Issues (High)

1. **No ES query caching** (`api/services/elasticsearch.py:101-170`)
   - High ES load on repeated searches
   - **Fix:** Cache results in Redis

2. **Sequential alert rule evaluation** (`api/routers/global_alert_rules.py:641-670`)
   - Slow for 50+ rules
   - **Fix:** Parallel execution with asyncio

3. **No connection pooling** (Multiple files)
   - High latency, port exhaustion
   - **Fix:** Implement pools for ES, MinIO, Redis

4. **Single-threaded plugin parsing** (`processor/tasks/ingest_task.py:113-120`)
   - Slow for large files
   - **Fix:** Producer-consumer pattern

### Code Quality Issues (Medium)

1. **Duplicate alert rule systems** (`alert_rules.py` vs `global_alert_rules.py`)
   - Maintenance burden, confusion
   - **Fix:** Deprecate per-case rules

2. **No retry logic for ES indexing** (`processor/utils/es_bulk.py:45-60`)
   - Data loss on transient failures
   - **Fix:** Add exponential backoff

3. **Silent exception handling** (`api/routers/global_alert_rules.py:670`)
   - Failed rules not reported
   - **Fix:** Log and report errors

4. **Hardcoded resource limits** (`processor/tasks/module_task.py:89-94`)
   - One-size-fits-all doesn't work
   - **Fix:** Per-module profiles

### Missing Features (Medium)

1. **No audit logging**
   - Can't track user actions
   - **Fix:** Log all write operations

2. **No case-level permissions**
   - All analysts see all cases
   - **Fix:** Add case_analysts field

3. **No real-time alerting**
   - Rules only run on-demand
   - **Fix:** Scheduled Celery task

4. **No task priorities**
   - Critical tasks blocked by low-priority
   - **Fix:** Add Celery priorities

---

## RECOMMENDATIONS

### Immediate Actions (Week 1-2)

1. Fix RBAC bypass in editor router
2. Add input validation for module parameters
3. Implement rate limiting on auth endpoints
4. Add retry logic for ES indexing
5. Fix silent exception handling in alert rules

### Short-term (Month 1)

1. Implement ES query caching
2. Add connection pooling (ES, MinIO, Redis)
3. Parallelize alert rule evaluation
4. Add audit logging
5. Implement per-module resource profiles

### Medium-term (Quarter 1)

1. Deprecate per-case alert rules
2. Add case-level permissions
3. Implement real-time alerting
4. Add task priorities
5. Encrypt memory dumps

### Long-term (Quarter 2+)

1. Migrate to async ES client
2. Implement Redis clustering
3. Add DLQ for failed tasks
4. Build producer-consumer for plugin parsing
5. Add API key support for service accounts

---

## APPENDIX A: File Inventory

**Total Python Files:** 82

**By Directory:**
- `api/`: 30 files (routers, services, auth, models)
- `processor/`: 12 files (tasks, utils, plugin_loader)
- `plugins/`: 18 plugin classes
- `collector/`: 1 file (collect.py - 1028 lines)
- `modules/`: 0 files (runtime volume)
- `elasticsearch/`: Not examined (K8s manifests only)

**Largest Files:**
1. `processor/tasks/module_task.py`: 3648 lines
2. `api/routers/llm_config.py`: 866 lines
3. `api/routers/global_alert_rules.py`: 737 lines
4. `collector/collect.py`: 1028 lines
5. `api/routers/modules.py`: 481 lines

---

## APPENDIX B: Plugin Inventory

**Built-in Plugins (18):**
1. access_log_plugin.py
2. android_plugin.py
3. browser_plugin.py
4. evtx_plugin.py
5. hayabusa_plugin.py
6. ios_plugin.py
7. lnk_plugin.py
8. log2timeline_plugin.py
9. macos_uls_plugin.py
10. mft_plugin.py
11. ndjson_plugin.py
12. pcap_plugin.py
13. plaso_plugin.py
14. prefetch_plugin.py
15. registry_plugin.py
16. suricata_plugin.py
17. syslog_plugin.py
18. zeek_plugin.py

---

**END OF AUDIT REPORT**
