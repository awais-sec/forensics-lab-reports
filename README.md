# Digital Forensics Portfolio

A series of hands-on digital forensics examinations covering disk acquisition, Windows
Registry analysis, credential recovery, file system internals, live memory forensics,
steganography, and mobile device forensics.

**Author:** Awais Ahmed
**Program:** B.S. Digital Forensics and Cyber Security (DFCS)
**Certification Track:** Certified Computer Forensics Analyst (CCFA)

## Reports

| # | Report | Focus |
|---|--------|-------|
| 1 | [Forensic Acquisition of a USB Storage Device](01-ftk-imager-usb-acquisition/README.md) | Bit-by-bit E01 imaging and hash verification with FTK Imager |
| 2 | [Windows Registry Artifact Analysis](02-windows-registry-forensics/README.md) | Full case investigation across 36 findings, cross-validated with Autopsy and RegRipper |
| 3 | [SAM Hash Extraction and Password Recovery](03-sam-hash-extraction/README.md) | Offline credential auditing with PwDump7, ophcrack, and Hash Suite |
| 4 | [NTFS File System and Master File Table Analysis](04-ntfs-mft-analysis/README.md) | MFT internals, resident vs. non-resident files, and deleted file recovery |
| 5 | [Live Memory Forensics with Volatility 3](05-volatility-memory-forensics/README.md) | RAM acquisition and plugin-based triage, including malware false-positive analysis |
| 6 | [GIF Steganography: Embedding and Extraction](06-gif-steganography/README.md) | LSB steganography and integrity verification |
| 7 | [Mobile Device Forensics via ADB](07-mobile-adb-forensics/README.md) | Live Android 13 acquisition and the limits of non-root access |

Reports 2, 3, and 4 form a connected case (the Mantooth case); findings in each
reference and build on the others.

## Practical Field Reference

A consolidated reference of tools, commands, file/registry paths, and operational notes
synthesized across all of the above: [DFCS Practical Field Reference](field-reference.md).
