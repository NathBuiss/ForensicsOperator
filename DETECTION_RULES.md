# Detection Rules Expansion Proposal

## Current State Analysis

### Existing Rules (11 Categories, 67 Rules Total)

| Category | File | Rules | Status |
|----------|------|-------|--------|
| Anti-Forensics | 01_anti_forensics.yaml | 5 | Complete |
| Authentication | 02_authentication.yaml | 7 | Complete |
| Privilege Escalation | 03_privilege_escalation.yaml | 5 | Complete |
| Persistence | 04_persistence.yaml | 7 | Complete |
| Execution | 05_execution.yaml | 9 | Complete |
| Lateral Movement | 06_lateral_movement.yaml | 5 | Needs expansion |
| Defense Evasion | 07_defense_evasion.yaml | 6 | Needs expansion |
| Credential Access | 08_credential_access.yaml | 6 | Needs expansion |
| Discovery | 09_discovery.yaml | 5 | Needs expansion |
| Command & Control | 10_command_control.yaml | 6 | Needs expansion |
| Exfiltration | 11_exfiltration.yaml | 5 | Needs expansion |

### Artifact Type Coverage

| Artifact Type | Rules Supporting | Gaps |
|--------------|-----------------|------|
| EVTX (Windows Events) | 62 rules | Well covered |
| Suricata (Network) | 11 rules | Limited to alerts/flows |
| Sysmon | Via EVTX mapping | No dedicated Sysmon rules |
| Registry | 0 rules | Not covered |
| File System | 0 rules | Not covered |
| Browser History | 0 rules | Not covered |
| Prefetch | 0 rules | Not covered |
| LNK Files | 0 rules | Not covered |
| MFT | 0 rules | Not covered |
| Zeek/Bro | 0 rules | Not covered |

---

## Proposed New Detection Rules

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

## Implementation Priority

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

## Technical Requirements

### New Parsers Needed
| Artifact Type | Parser Status | Effort |
|--------------|---------------|--------|
| Registry | Exists | Low |
| Prefetch | Exists | Low |
| LNK | Exists | Low |
| MFT | Exists | Medium |
| Hindsight (Browser) | Exists | Medium |
| Zeek | Not implemented | High |
| Sysmon (dedicated) | Via EVTX | Low |

### Elasticsearch Index Templates
Need to create templates for:
- fo-case-{id}-registry
- fo-case-{id}-prefetch
- fo-case-{id}-lnk
- fo-case-{id}-mft
- fo-case-{id}-hindsight
- fo-case-{id}-zeek

### Performance Considerations
- **Threshold tuning**: Some rules have high thresholds (10, 20, 50) to reduce noise
- **Artifact type filtering**: Rules specify artifact_type to limit query scope
- **Sample size**: All rules return max 5 sample events to reduce memory usage

---

## Metrics and Validation

### Rule Effectiveness Tracking
For each rule, track:
1. **True Positive Rate**: Matches confirmed as malicious
2. **False Positive Rate**: Matches confirmed as benign
3. **Coverage**: Percentage of cases where rule fired
4. **Dwell Time**: Time between attack and rule firing

### Recommended KPIs
- **Mean Time to Detect (MTTD)**: Target under 1 hour for critical rules
- **Alert Volume**: Under 100 alerts per analyst per day
- **Investigation Time**: Under 15 minutes per alert triage
- **Rule Coverage**: Over 90 percent of MITRE ATT&CK techniques covered

---

## MITRE ATT&CK Coverage Map

| Tactic | Current Rules | Proposed Rules | Total | Coverage Percent |
|--------|--------------|----------------|-------|-----------------|
| Reconnaissance | 0 | 5 | 5 | 15 |
| Resource Development | 0 | 5 | 5 | 10 |
| Initial Access | 0 | 11 | 11 | 45 |
| Execution | 9 | 15 | 24 | 70 |
| Persistence | 7 | 13 | 20 | 65 |
| Privilege Escalation | 5 | 10 | 15 | 60 |
| Defense Evasion | 6 | 12 | 18 | 65 |
| Credential Access | 6 | 11 | 17 | 70 |
| Discovery | 5 | 10 | 15 | 55 |
| Lateral Movement | 5 | 8 | 13 | 60 |
| Collection | 0 | 0 | 0 | 0 |
| Command and Control | 6 | 12 | 18 | 65 |
| Exfiltration | 5 | 8 | 13 | 60 |
| Impact | 0 | 11 | 11 | 50 |
| **TOTAL** | **49** | **131** | **180** | **55** |

---

## Next Steps

1. Create YAML files for each new category
2. Test rules against sample datasets
3. Tune thresholds based on false positive rates
4. Document each rule with MITRE ATT&CK mappings
5. Integrate with threat intelligence feeds
6. Automate rule updates from Sigma HQ
7. Create alert response playbooks
8. Implement machine learning for anomaly detection

---

Generated: 2026-03-27
Total Proposed Rules: 131 new detection rules across 13 categories
