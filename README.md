# forensics-lab-reports

**CCFA Forensic Case Reports** — Seven complete digital forensic investigations completed as part of the Certified Computer Forensics Analyst (CCFA) certification through eSecurity Institute (July 2026).

Each report follows a structured investigation workflow: acquisition, analysis, findings, and conclusions — documented to professional chain-of-custody standards.

---

## Reports

| # | Case | Techniques | Tools |
|---|---|---|---|
| 01 | FTK Imager USB Acquisition | Forensic imaging, hash verification, evidence packaging | FTK Imager, MD5/SHA1, Write Blocker |
| 02 | NTFS File System MFT Analysis | MFT parsing, deleted file recovery, timestamp analysis | Autopsy, MFTECmd, EZTools |
| 03 | Windows Registry Forensics | Hive analysis, user activity, USB history, recently accessed | Registry Editor, Autopsy |
| 04 | SAM Hash Extraction & Password Recovery | NTLM hash extraction, rainbow table cracking | pwdump7, Ophcrack, Hash Suite |
| 05 | GIF Steganography Detection | Pixel-level analysis, hidden payload extraction | gif-steganography, Python |
| 06 | Live Memory Forensics | RAM acquisition, process enumeration, network scan, code injection detection | Volatility 3, DumpIt |
| 07 | Mobile Forensics via ADB | Android artifact extraction, app data, call logs, SMS | ADB, Android 13 |

---

## Tools & Environment

- **Autopsy** — Disk forensics and timeline analysis
- **Volatility 3** — Memory forensics (pslist, netscan, malfind, cmdline, dlllist, pstree, dumpfiles)
- **FTK Imager** — Forensic acquisition and imaging
- **MFTECmd / EZTools** — NTFS Master File Table parsing
- **pwdump7 / Ophcrack / Hash Suite** — Credential extraction and cracking
- **ADB (Android Debug Bridge)** — Mobile device forensics
- **gif-steganography** — Steganography detection

---

## Framework

All investigations documented following:
- NIST SP 800-86 (Guide to Integrating Forensic Techniques)
- Chain-of-custody standards
- Evidence integrity verification (MD5/SHA1 hashing)

---

## Author

**Awais Ahmed** — Security Operations Analyst | DFIR Practitioner  
[Portfolio](https://awais-sec.github.io) · [LinkedIn](https://www.linkedin.com/in/awais-sec/) · [TryHackMe](https://tryhackme.com/p/Dr.04x)
