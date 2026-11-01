# mlwr_detects

Script to get detects from VirusTotal and MalwareBazaar by hash

### Requirements

- ```aiohttp>=3.9.0```
- VirusTotal API Key
- MalwareBazaar Auth Key

### Usage

```bash
python3 mlwr_detects.py    
usage: mlwr_detects.py [-h] [--json] [--no-color] hash
mlwr_detects.py: error: the following arguments are required: hash

```

### Example

```bash
python3 mlwr_detects.py 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e

File Hash: 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e


─── VIRUSTOTAL ───
Meaningful name: 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e.exe
Names: 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e.exe, 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e.bin, m2x5d57i4.exe, 4536297338323C00783FDCEABF8D36BF, 7ad1bf03b480ebd2b85b2bc5be4b9140b0ce6d4d
Type: Win32 EXE
Size: 916992 bytes
Tags: spreader, runtime-modules, peexe, direct-cpu-clock-access, obfuscated, calls-wmi
Stats: Malicious: 54 | Suspicious: 0 | Undetected: 14 | Harmless: 0

Detections:
  🔴 ALYac [malicious] → Trojan.Ransom.MedusaLocker
  🔴 APEX [malicious] → Malicious
  🔴 AhnLab-V3 [malicious] → Malware/Win32.Generic.C4176634
  🔴 Alibaba [malicious] → Trojan:Win32/Emotet.92d4ba2a
  🔴 Antiy-AVL [malicious] → Trojan/Win32.GenKryptik
  🔴 Arcabit [malicious] → Trojan.Generic.D4E37AF1
  🔴 Avira [malicious] → TR/W32.Trojan
  🔴 BitDefender [malicious] → Trojan.GenericKD.82017009
  🔴 Bkav [malicious] → W32.Malware.D7ED33A6
  🔴 CTX [malicious] → exe.trojan.generic
  🔴 CrowdStrike [malicious] → win/malicious_confidence_100% (W)
  🔴 Cylance [malicious] → Unsafe
  🔴 Cynet [malicious] → Malicious (score: 100)
  🔴 DeepInstinct [malicious] → MALICIOUS
  🔴 DrWeb [malicious] → Trojan.DownLoader34.18175
  🔴 ESET-NOD32 [malicious] → Win32/Kryptik.HFKY trojan
  🔴 Elastic [malicious] → malicious (high confidence)
  🔴 Emsisoft [malicious] → Trojan.GenericKD.82017009 (B)
  🔴 F-Secure [malicious] → Trojan.TR/W32.Trojan
  🔴 Fortinet [malicious] → W32/Kryptik.HFBI!tr
  🔴 GData [malicious] → Trojan.GenericKD.82017009
  🔴 Google [malicious] → Detected
  🔴 Gridinsoft [malicious] → Ransom.Win32.TrickBot.oa!s1
  🔴 Jiangmin [malicious] → Trojan.Banker.Emotet.ppi
  🔴 K7AntiVirus [malicious] → Trojan ( 0060fe941 )
  🔴 K7GW [malicious] → Trojan ( 0060fe941 )
  🔴 Kaspersky [malicious] → Trojan-Banker.Win32.Emotet.fobo
  🔴 Kingsoft [malicious] → Win32.Trojan-Banker.Emotet.gen
  🔴 Lionic [malicious] → Trojan.Win32.Emotet.L!c
  🔴 Malwarebytes [malicious] → Generic.Malware/Suspicious
  🔴 MaxSecure [malicious] → Trojan.Malware.11417434.susgen
  🔴 McAfeeD [malicious] → ti!9814F9D8A8B1
  🔴 MicroWorld-eScan [malicious] → Trojan.GenericKD.82017009
  🔴 Microsoft [malicious] → Trojan:Win32/Trickbot!pz
  🔴 NANO-Antivirus [malicious] → Trojan.Win32.Emotet.hqrhky
  🔴 Paloalto [malicious] → generic.ml
  🔴 Panda [malicious] → Trj/CI.A
  🔴 Rising [malicious] → Trojan.Trickbot!1.CA23 (CLASSIC)
  🔴 Sangfor [malicious] → Trojan.Win32.Kryptik.V0si
  🔴 SentinelOne [malicious] → Static AI - Suspicious PE
  🔴 Skyhigh [malicious] → Emotet-FSA!453629733832
  🔴 Sophos [malicious] → Mal/Generic-S
  🔴 Symantec [malicious] → Trojan.Emotet
  🔴 Tencent [malicious] → Malware.Win32.Gencirc.10c0fdb4
  🔴 Trapmine [malicious] → malicious.moderate.ml.score
  🔴 TrellixENS [malicious] → Emotet-FSA!453629733832
  🔴 TrendMicro [malicious] → TrojanSpy.Win32.TRICKBOT.USBLHA26
  🔴 VIPRE [malicious] → Dump:Generic.ShellCode.RDI.Marte.1.825E9E29
  🔴 Varist [malicious] → W32/ABTrojan.IRQD-0612
  🔴 ViRobot [malicious] → Trojan.Win32.Z.Emotet.916992
  🔴 Xcitium [malicious] → Malware@#17kbdptlsecb6
  🔴 Yandex [malicious] → Trojan.AD!UpmcO+k1DTY
  🔴 alibabacloud [malicious] → Trojan[stealer]:Win/Trickbot.Gen
  🔴 huorong [malicious] → Trojan/Generic!639C793E0A14F769

Link: https://www.virustotal.com/gui/file/9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e

────────────────────────────────────────────────────────────

─── MALWAREBAZAAR ───
SHA256: 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e
SHA1:   7ad1bf03b480ebd2b85b2bc5be4b9140b0ce6d4d
MD5:    4536297338323c00783fdceabf8d36bf
SHA3-384: 47079b0152f8bf96542c2c83e7fdee0eb47b1e07709a568e4581a09a864db02e7c77eb6d2c6e9e89b207725578f55ea7
File name: 9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e.bin
File type: exe (application/vnd.microsoft.portable-executable)
File size: 916992 bytes
Signature: MedusaLocker
Tags: exe, Medusalocker, ransom
First seen: 2026-10-30 11:34:12
Last seen:  2026-10-30 12:32:14
Reporter: magolexa_
Origin country: FR
Anonymous: 0
Imphash: e3b6e7113c1fc5203c1761beebcb7533
ssdeep: 24576:cpujQRfL2Zsfeik9HV+Ovkd4pBWLv01oqc1cTfOAf:cpbDYIk91/pIL0cYf
TLSH:   T1F1151212B0C38477D2A12535063DB5708AB9FE300E39DB9B7BC8C26B5E1A5D1EB39706

YARA rules:
  - DebuggerCheck__API
      https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara
  - exploit_any_poppopret (author: Jeff White [karttoon@gmail.com] @noottrak)
      Identify POP -> POP -> RET opcodes for quick ROP Gadget creation in target binaries.
  - golang_bin_JCorn_CSC846 (author: Justin Cornwell)
      CSC-846 Golang detection ruleset
  - TH_AntiVM_MassHunt_Win_Malware_2026_CYFARE (author: CYFARE)
      Detects Windows malware employing anti-VM / anti-sandbox evasion techniques across VMware, VirtualBox, Hyper-V, QEMU, Xen, and generic sandbox environments
      https://cyfare.net/
  - VECT_Ransomware (author: Mustafa Bakhit)
      Detects activity associated with VECT ransomware. This includes registry modifications and deletions, execution of system and defense-evasion commands, suspicious API usage, mutex creation, file and memory manipulation, ransomware note generation, anti-debugging and anti-analysis techniques, and embedded cryptographic constants (SHA256) characteristic of this malware family. Designed for threat intelligence and malware detection environments.
  - WIN_Malware_ACRStealer_ForgeAuto_1084c837_Extrait (author: Marjoriefort)
      Detects ACRStealer (pe, etat extrait)
  - WIN_Malware_Fantom_ForgeAuto_98e6f354_Extrait (author: Marjoriefort)
      Detects Fantom (pe, etat extrait)
  - WIN_Malware_Unknown_ForgeAuto_5001c94c (author: Marjoriefort)
      Detects Unknown (pe, etat binaire)

Vendor intel:
  CERT-PL_MWDB: link=https://mwdb.cert.pl/sample/9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e/
  YOROI_YOMI: score=1.00 | detection=Malicious File
  Intezer: verdict=malicious | analysis_url=https://analyze.intezer.com/analyses/dddb36fe-6b7f-4c82-acf5-713e1dc28c9c?utm_source=MalwareBazaar
  CAPE: detection=MedusaLocker | link=https://www.capesandbox.com/analysis/96214/
  Triage: score=10 | malware_family=medusalocker | tags=family:medusalocker, defense_evasion, discovery, ransomware, spyware, stealer, trojan | signatures={'signature': 'Family: MedusaLocker', 'score': '10'}, {'signature': 'MedusaLocker payload', 'score': '10'}, {'signature': 'UAC bypass', 'score': '10'}, {'signature': 'Renames multiple (116) files with added filename extension', 'score': '9'}, {'signature': 'Executes dropped EXE', 'score': '7'}, {'signature': 'Reads user/profile data of web browsers', 'score': '7'}, {'signature': 'Checks whether UAC is enabled', 'score': '6'}, {'signature': 'Drops desktop.ini file(s)', 'score': '6'}, {'signature': 'Enumerates connected drives', 'score': '6'}, {'signature': 'Enumerates physical storage devices', 'score': '3'}, {'signature': 'Reads the TCP/IP host and domain name from the registry', 'score': '3'}, {'signature': 'System Location Discovery: System Language Discovery', 'score': '3'}, {'signature': 'Suspicious behavior: EnumeratesProcesses', 'score': None}, {'signature': 'Suspicious use of AdjustPrivilegeToken', 'score': None}, {'signature': 'Suspicious use of WriteProcessMemory', 'score': None}, {'signature': 'System policy modification', 'score': None} | link=https://tria.ge/reports/261030-n4fwtaby5z/
  ReversingLabs: threat_name=Win32.Trojan.TrickBot
  VMRay: verdict=malicious | report_link=https://www.vmray.com/analyses/_mb/9814f9d8a8b1/report/overview.html
  FileScan-IO: report_link=https://www.filescan.io/uploads/6ae48628869b93e00bec9f19/reports//overview
  Kaspersky: verdict=Malware | report_link=https://opentip.kaspersky.com/9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e/results?tab=lookup

Link: https://bazaar.abuse.ch/sample/9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e/


```