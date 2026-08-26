# DFCS Practical Field Reference

*Tools, Commands, and Core Concepts Across Nine Hands-On Forensic Disciplines*

**Author:** Awais Ahmed
**Program:** B.S. Digital Forensics and Cyber Security (DFCS)
**Certification Track:** Certified Computer Forensics Analyst (CCFA)

---

About This Reference

This document consolidates the practical, hands-on knowledge developed
across a series of independent digital forensics examinations: acquiring
a forensic disk image, reconstructing a case from Windows Registry
artifacts, recovering account credentials, analyzing the NTFS file
system at the MFT level, performing live memory forensics, working with
steganography, and conducting mobile device acquisition.

Each section below reflects tools actually run and commands actually
executed during that work, not a summary of documentation. Where a step
has a common failure mode or a detail that's easy to get wrong, that's
noted directly alongside the command it applies to, the same way a
practitioner would flag it for a colleague.

For full case context, methodology, and findings behind any individual
section, the corresponding standalone report is available on request.

## 1. Windows Registry Forensics

### Tools

*Autopsy 4.23.1 \| RegRipper 3.0 (plugin-based hive parser) \| FTK
Imager (hive export) \| Registry Editor (live host comparison)*

### Hive Locations

C:\Windows\System32\config\SAM \| SECURITY \| SOFTWARE \| SYSTEM  
C:\Users<user>\NTUSER.DAT

### Key Registry Paths

|                        |                                                                                                                   |
|------------------------|-------------------------------------------------------------------------------------------------------------------|
| **Artifact**           | **Path**                                                                                                          |
| **Computer name**      | SYSTEM\ControlSet001\Control\ComputerName\ComputerName                                                            |
| **Time zone**          | SYSTEM\ControlSet001\Control\TimeZoneInformation                                                                  |
| **Prefetch setting**   | SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters                                 |
| **Service start type** | SYSTEM\ControlSet001\Services\\service name\> (Start: 0=Boot 1=System 2=Auto 3=Demand 4=Disabled)                 |
| **Last shutdown time** | SYSTEM\ControlSet001\Control\Windows (ShutdownTime, FILETIME)                                                     |
| **USB device history** | SYSTEM\ControlSet001\Enum\USBSTOR                                                                                 |
| **Wireless profiles**  | SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\\GUID} (NameType 0x47 = wireless, 0x06 = wired) |
| **Installed software** | SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall                                                               |
| **OS registration**    | SOFTWARE\Microsoft\Windows NT\CurrentVersion (RegisteredOwner/Org, ProductId, InstallDate)                        |
| **User profiles**      | SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList                                                          |
| **SAM account data**   | SAM\SAM\Domains\Account\Users\\RID\>                                                                              |
| **Recent docs / MRU**  | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs, and \Explorer\ComDlg32\OpenSavePidlMRU  |
| **IE settings**        | NTUSER.DAT\Software\Microsoft\Internet Explorer\Main / Favorites / TypedURLs                                      |
| **Media Player MRU**   | NTUSER.DAT\Software\Microsoft\MediaPlayer\Player\RecentFileList                                                   |
| **Run box history**    | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU                                              |
| **VNC password**       | SOFTWARE\RealVNC\WinVNC4 (Password, DES-obfuscated with a fixed key)                                              |
| **Yahoo Messenger**    | NTUSER.DAT\Software\Yahoo\Pager                                                                                   |

### Operational Notes

- RID convention: 500 is always the built-in Administrator, 501 is
always the built-in Guest, 1000+ are regular user accounts in creation
order.

- SAM samparse fields worth comparing across accounts: Login Count,
Last Login, Pwd Fail Date. Near-simultaneous failed logins across two
different accounts is a pattern worth investigating, not dismissing.

- Cross-validate every finding: Autopsy view against RegRipper
plugin output against a live host for comparison. A single-tool finding
should be treated as provisional until confirmed a second way.

- An empty or unset LM hash is normal from Windows Vista onward,
since LM hashing is disabled by default. It is not evidence of
tampering.

## 2. Credential Recovery: SAM Hash Extraction and Cracking

### Tools

*PwDump7 1.0 (hash extraction) \| ophcrack (rainbow tables) \| Hash
Suite 4.0 Free (dictionary attack, rockyou.txt)*

*Hash Suite can also extract NTLM hashes directly from a live or local
system, not only crack an already-extracted hash file. Ophcrack
specifically targets NTLM hashes pulled from the SAM+SYSTEM hive pair.*

### Commands

```
PwDump7.exe -s "C:\Users\<user>\Desktop\pwdump7\hives\SAM" "C:\Users\<user>\Desktop\pwdump7\hives\SYSTEM"
PwDump7.exe -s "C:\Users\<user>\Desktop\pwdump7\hives\SAM" "C:\Users\<user>\Desktop\pwdump7\hives\SYSTEM" > all_hashes.txt
```

ophcrack: Load, PWDUMP file, select all_hashes.txt, then Tables, install
the table set matching the target OS (e.g. Vista free for a Vista
system).

Hash Suite: Key, Import, From file, all_hashes.txt. Set Params, wordlist
= rockyou.txt. Set Main, Format = NTLM (must be set explicitly).

### Operational Notes

- SAM stores encrypted hashes; SYSTEM holds the boot key needed to
decrypt them. Both files are required together, neither is useful alone.

- LM hash: legacy, weak, disabled by default since Vista (shows as a
constant placeholder). NT/NTLM hash: the real target, an MD4 digest of
the UTF-16LE password.

- Empty-password NT hash constant, worth recognizing on sight:
31d6cfe0d16ae931b73c59d7e0c089c0

- Rainbow tables (ophcrack) are fast and precomputed, but bounded by
whatever charset and length the table was built for. Wordlists (Hash
Suite) work on the fly and catch real breached passwords outside a
table's coverage. Running both and getting matching results is
meaningful cross-validation, not redundant effort.

- Hash Suite's format must be set to NTLM explicitly: a raw hex hash
does not self-identify its algorithm (the same 32-character hex could be
NTLM or raw MD5), and the wrong format produces a silent failure even
with the correct password present in the wordlist.

- PwDump7 is routinely flagged by antivirus as a dual-use
'hacktool.' Expect to disable real-time protection to download it, then
re-enable protection immediately after.

## 3. Steganography (LSB Techniques)

Tool

*gif-steganography (Python package, requires Python 3.12). Dependencies:
Pillow (image I/O), cryptography (payload encryption), numpy (pixel
arrays), reedsolo (error-correcting redundancy).*

### Commands

```
gif-steganography encode "input.gif" "output.gif" "message" "passphrase"
gif-steganography decode "output.gif" "passphrase"

certutil -hashfile input.gif SHA256
certutil -hashfile output.gif SHA256
```

### Operational Notes

- LSB steganography overwrites the least-significant bit(s) of pixel
data with message bits. In true-color images this is visually
imperceptible (a 1/255 channel shift); in palette-indexed formats like
GIF, flipping the LSB of the palette index can jump to a visibly
different color, so artifacts are common and expected specifically in
GIF.

- Steganography is not limited to images: any image, audio, or video
file can serve as a carrier. The underlying principle, hiding data in
the least-noticeable part of the carrier, is the same across formats;
only the embedding mechanism changes.

- Tools are generally not cross-compatible with one another: they
differ in bit position, target channel or index, pixel scan order, and
payload framing. Always decode with the same tool used to encode.

- Hashing the carrier before and after (SHA-256) is the rigorous
proof that the file changed at the byte level. Visual similarity alone
proves nothing.

## 4. Live Memory Forensics (Volatility 3)

### Tools

*DumpIt (RAM acquisition), followed by Volatility 3 Framework (Python
3.12) for analysis.*

### Setup and Core Plugins

```
pip install --user -e ".[full]"

python vol.py -f memory.dmp windows.info
python vol.py -f memory.dmp windows.pslist
python vol.py -f memory.dmp windows.netscan
python vol.py -f memory.dmp windows.pstree
python vol.py -f memory.dmp windows.cmdline
python vol.py -f memory.dmp windows.malware.malfind
python vol.py -f memory.dmp windows.filescan
```

### Targeted Filtering

--pid \<PID\> restrict to a single process  
--name "pattern\*" filter by process name (wildcards supported)  
--regex "pattern" filter using a full regular expression  
--dump (malfind) export the flagged region to disk

### Plugin Reference

|                             |                                                                                  |
|-----------------------------|----------------------------------------------------------------------------------|
| **Plugin**                  | **Purpose**                                                                      |
| **windows.info**            | Confirms OS build and profile before trusting any other plugin's output          |
| **windows.pslist**          | Running processes: PID, PPID, thread/handle counts, creation time                |
| **windows.netscan**         | TCP/UDP endpoints and owning process, including some recently-closed connections |
| **windows.pstree**          | Same process set as pslist, organized by parent-child tree                       |
| **windows.cmdline**         | Exact launch arguments (surfaces a malformed -k argument on svchost.exe)         |
| **windows.malware.malfind** | Flags PAGE_EXECUTE_READWRITE memory regions, a classic injection signal          |
| **windows.filescan**        | Open and recent file objects, including kernel driver and NTFS metadata files    |

### Operational Notes

- malfind flags the RWX memory-permission pattern, not injection
itself. Antivirus engines running their own sandbox/emulation, and OEM
utilities, are common, well-documented false positives. Always triage
the finding; don't report it at face value.

- A legitimate svchost.exe instance always carries a named -k
service-group argument (for example, -k LocalService). A blank or
malformed argument is the actual red flag.

## 5. NTFS File System and Master File Table Analysis

### Tools

*Autopsy (browse volume and MFT properties) and Eric Zimmerman's MFTECmd
/ EZTools (parses a raw $MFT or $MFTMirr file into CSV).*

Workflow: extract $MFT and $MFTMirr from the image first, via
Autopsy's export feature or FTK Imager, then run MFTECmd against the
extracted file. MFTECmd parses a raw hive/table file already on disk; it
does not read the source image directly.

### Commands

```
MFTECmd.exe -f "path\to\$MFT" --csv "output_folder"
MFTECmd.exe -f "path\to\$MFTMirr.copy0" --csv "output_folder"
```

### Core NTFS System Files

|            |                                            |
|------------|--------------------------------------------|
| **Record** | **File / Purpose**                         |
| **0**      | $MFT, the master file table itself        |
| **1**      | $MFTMirr, a backup of records 0 through 3 |
| **2**      | $LogFile, the transaction/journal log     |
| **3**      | $Volume, volume label and dirty flag      |

### Operational Notes

- $MFTMirr size is always 4,096 bytes, equal to 4 records at 1,024
bytes each. It only ever backs up records 0 through 3, never more.
Verify both by dividing size by 1,024 and with an independent MFTECmd
parse.

- Resident file: small enough to fit inside its own 1,024-byte MFT
record, with content stored inline and no data runs. Non-resident: too
large for the record, which instead holds data-run pointers to clusters
elsewhere on the volume.

- MACB timestamps: Modified, Accessed, Created, and (MFT)
entry-modified.

- Since Windows Vista, automatic last-access-time updates are
disabled by default (NtfsDisableLastAccessUpdate). Simply opening or
viewing a file will typically NOT update its Accessed timestamp on a
modern default install. Access time should not be treated as reliable
'last opened' evidence unless this setting has been confirmed on the
specific system.

## 6. Forensic Acquisition with FTK Imager

Tool

*AccessData FTK Imager (Windows). File, Create Disk Image.*

### Workflow

- 1. Select Source: Physical Drive (the whole device, including its
partition table) versus Logical Drive (a single partition only).

- 2. Select the exact drive from the list. Confirm by size and
interface string before proceeding, since this step cannot be undone.

- 3. Destination image type: E01 (EnCase) is usually the right
choice. It embeds hashes and case metadata directly in the file and
supports compression.

- 4. Evidence Item Information: Case Number, Evidence Number, Unique
Description, Examiner, Notes. This gets embedded in the E01 header as
part of chain of custody.

- 5. Image Destination: folder, filename, fragment size (for example
1500 MB), and compression level (0 = none through 9 = smallest).

- 6. Review the summary, and confirm 'Verify images after they are
created' is checked before starting.

- 7-8. Acquisition runs sector by sector; status ends with 'Image
created successfully.'

- 9. Verify: FTK re-hashes the image (MD5 and SHA-1) and compares
both against the source hash. Both must report Match, and Bad Blocks
should read none.

### Image Format Reference

|                  |                                                                           |
|------------------|---------------------------------------------------------------------------|
| **Format**       | **Note**                                                                  |
| **Raw (dd)**     | A pure sector copy with no embedded metadata or hashes                    |
| **SMART**        | An older ASR Data format, rarely used today                               |
| **E01 (EnCase)** | Embeds hashes and case metadata, supports compression; the default choice |
| **AFF**          | An open container format with less universal tool support than E01        |

### Operational Notes

- A forensic image captures every sector, including deleted data and
unallocated space. A normal copy-paste only grabs live, visible files,
and can alter source timestamps in the process.

- A matching MD5 and SHA-1 (two independent algorithms) proves
bit-for-bit integrity: changing even a single bit anywhere changes the
entire hash, with no practical way to fake a match in both
simultaneously.

## 7. Mobile Device Forensics via ADB

Tool

*Android SDK Platform-Tools (ADB). Requires Developer Options unlocked
(tap Build Number seven times), USB Debugging enabled, and the on-device
authorization prompt accepted.*

### Core Commands

adb devices confirm the device shows "device", not "unauthorized"  
adb shell getprop full system property dump  
adb shell getprop ro.product.model  
adb shell getprop ro.build.version.release  
adb shell getprop ro.serialno  
adb shell pm list packages -f installed packages and install path  
adb logcat -d \> logs.txt dump-and-exit log capture  
adb shell dumpsys battery charging state, voltage, current  
adb shell ifconfig interfaces and IPv6 addresses (check Scope: Global vs
Link)  
adb shell netstat active connections and TCP state  
adb pull /sdcard/DCIM ./local_folder file/directory extraction (no root
needed for /sdcard)  
adb pull /data/system/packages.list returns "Permission denied": /data
needs root or a forensic-mode image  
adb shell dumpsys usagestats recent app and account activity  
adb shell dumpsys batterystats timestamped power and activity history  
adb shell settings list system device and account settings dump

### Restricted on Android 11+ (Requires Root or a Forensic Build)

adb shell dumpsys account apps with registered accounts  
adb shell content query --uri content://contacts/phones/  
adb shell content query --uri content://call_log/calls  
adb shell content query --uri content://sms/  
adb shell settings list global \| grep "boot_count="

### Reading netstat Connection States

|                                       |                                                                                                             |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **State**                             | **Meaning**                                                                                                 |
| **ESTABLISHED**                       | A genuinely live, open session at the exact moment of capture; the strongest evidence in a network snapshot |
| **FIN_WAIT1 / LAST_ACK / CLOSE_WAIT** | Somewhere in TCP's closing handshake; proves recent activity, not still-active use                          |

### Operational Notes

- ADB access always requires physical, visible owner consent through
the authorization prompt. It cannot be performed silently.

- Android 11 and higher blocks shell access to Content Providers
(contacts, call log, SMS) and to /data. Both restrictions share the same
underlying sandboxing boundary, bypassed only by root access or an
official forensic acquisition build.

## 8. Archive, Office, and PDF Password Cracking (John the Ripper)

Tool

*John the Ripper, using format-specific '2john' helper scripts that
convert a protected file into a crackable hash.*

### Procedure

- 1. Choose the correct 2john helper for the file type: zip2john for
ZIP, rar2john for RAR, office2john for Word/Excel/PowerPoint, pdf2john
for PDF.

- 2. Extract the hash from the protected file into a text file.

```
zip2john "path\to\file.zip" > hash.txt
rar2john "path\to\file.rar" > hash.txt
office2john "path\to\file.docx" > hash.txt
pdf2john "path\to\file.pdf" > hash.txt
```

- 3. Run John against the extracted hash with a wordlist.

```
john --wordlist="path\to\wordlist.txt" hash.txt
```

- 4. Show the cracked result once John finishes.

```
john --show hash.txt
```

### Operational Notes

- Folders themselves do not have passwords, only archive files
(ZIP/RAR/7z) do. If the evidence is a folder, it must first be
compressed into a password-protected archive before a 2john script can
extract anything from it.

- The 2john script name always matches the file type, not the
underlying tool: zip2john for .zip, rar2john for .rar, office2john for
Word/Excel/PowerPoint (.docx/.xlsx/.pptx), pdf2john for .pdf.

- john --show only reveals a password after a successful crack. If
the wordlist does not contain the password, --show returns nothing to
display.

## 9. Recovering Saved Browser Passwords (Firefox Decrypt)

Tool

*firefox_decrypt.py, a Python tool that decrypts and extracts saved
logins from a Firefox profile's logins.json (encrypted credentials) and
key4.db (decryption key database).*

### Command

```
python firefox_decrypt.py -p "C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<your_profile>"
```

### Operational Notes

- The -p / --profile flag must point directly at the specific
Firefox profile folder, the one that actually contains logins.json and
key4.db, not the general Firefox installation folder.

- Firefox profile folders live under
%APPDATA%\Mozilla\Firefox\Profiles\\ by default. Each profile has an
auto-generated folder name ending in a random suffix (for example,
xxxxxxxx.default-release).

- logins.json holds the encrypted username/password pairs; key4.db
holds the key needed to decrypt them. Both files must be present
together for the tool to function.
