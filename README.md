<p align="center">
  <img src=".github/icon.png" width="128" alt="LabDC app icon">
</p>

# LabDC

**An Active Directory–compatible domain controller for your Mac — with a built-in RADIUS server for 802.1X Wi-Fi and wired, and its own certificate authority.**

LabDC is written from scratch in Swift and SwiftUI. Windows 10/11 PCs join its domain, users
sign in with Kerberos and NTLM, and access points and switches authenticate Wi-Fi and wired
clients against the same accounts — all from one app, one process and one folder on your Mac.
No Windows Server, no Samba, no `sudo`.

## ⬇️ Download

[![Download LabDC for macOS](https://img.shields.io/badge/Download-LabDC_1.1_%282%29_for_macOS-2ea44f?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/bestonehxh/LabDC/releases/latest)

**[Get the latest release →](https://github.com/bestonehxh/LabDC/releases/latest)** — download `LabDC-1.1-2.zip`, unzip, and drag **LabDC.app** into `Applications`.

> The build is unsigned (not notarized), so macOS will warn on first launch —
> right-click the app and choose **Open**, or run
> `xattr -dr com.apple.quarantine /Applications/LabDC.app`
>
> Requires macOS 26 or later, Apple Silicon.

## The Sheep family 🐑

LabDC sits next to a few small native macOS apps for network engineers:

|  | App | What it does |
|---|---|---|
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepTerm/main/.github/icon.png?v=3" width="48" height="48" alt="SheepTerm"> | **[SheepTerm](https://github.com/bestonehxh/SheepTerm)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepTerm/releases/latest) | SSH / Serial / local-shell terminal for network engineers |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepText/main/.github/icon.png?v=3" width="48" height="48" alt="SheepText"> | **[SheepText](https://github.com/bestonehxh/SheepText)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepText/releases/latest) | Fast text editor with tree-sitter highlighting and a JavaScript plugin system |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepDrop/main/.github/icon.png?v=3" width="48" height="48" alt="SheepDrop"> | **[SheepDrop](https://github.com/bestonehxh/SheepDrop)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepDrop/releases/latest) | SFTP / SCP / FTP / TFTP file transfer — client and built-in server |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepTap/main/.github/icon.png?v=3" width="48" height="48" alt="SheepTap"> | **[SheepTap](https://github.com/bestonehxh/SheepTap)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepTap/releases/latest) | Menu-bar viewer for your Mac's network interfaces with click-to-copy |
| <img src="https://raw.githubusercontent.com/bestonehxh/LabDC/main/.github/icon.png" width="48" height="48" alt="LabDC"> | **[LabDC](https://github.com/bestonehxh/LabDC)**<br>[⬇️ Download](https://github.com/bestonehxh/LabDC/releases/latest) | Active Directory–compatible domain controller with RADIUS for 802.1X and a lab CA |
| <img src="https://raw.githubusercontent.com/bestonehxh/SheepLog/main/.github/icon.png?v=2" width="48" height="48" alt="UncleSpy"> | **[UncleSpy](https://github.com/bestonehxh/SheepLog)**<br>[⬇️ Download](https://github.com/bestonehxh/SheepLog/releases/latest) | Syslog viewer, SNMP tester and packet capture with TCP and 802.1X ladder diagrams — and a Troubleshoot page that reads all three |

## Features

### Directory
- **Domain join for Windows 10/11** — DNS with the SRV records Windows looks for, CLDAP, LDAP/LDAPS and Global Catalog, SMB with the NETLOGON, SAMR, LSA and DRSUAPI pipes, and SYSVOL with Group Policy
- **Kerberos KDC and kpasswd**, NTLM, password policy, lockout, "must change password at next logon"
- **People, groups, computers and OUs** in a quiet, text-first app — plus a `labdc` command line for scripts
- **Rename the domain** in place, **profiles** for several labs side by side, backups and Start over
- **Secure dynamic DNS updates** (GSS-TSIG), **DPAPI backup keys** (MS-BKRP) and Kerberos delegation, as Windows expects from a DC

### RADIUS and 802.1X
- **WPA2-Enterprise, WPA3-Enterprise and WPA3-Enterprise 192-bit**, wireless and wired
- **EAP-TLS, PEAP-MSCHAPv2 and EAP-TTLS** (PAP, MS-CHAPv2, EAP-MSCHAPv2, EAP-GTC) over TLS 1.2 and 1.3, with fast reconnect and PEAP crypto binding
- **Change an expired password at Wi-Fi logon**
- **Policies with AND/OR conditions** on groups, OUs, SSID, NAS, time of day and more — return VLANs and vendor attributes
- **CoA and Disconnect**, MAC authentication bypass, accounting and session views
- **802.1X profiles pushed to Windows by Group Policy**, wired and wireless — several Wi-Fi profiles, GPMC-style options, and a per-profile RADIUS server: this DC or another one such as ClearPass, trusting its own or self-signed certificate

### DHCP
- **DHCPv4 and DHCPv6** beside your existing DHCP server, reached through relays for many VLANs
- Reservations, leases, **dynamic DNS**, vendor option 43 for access points, and **device profiling** that feeds RADIUS policies

### Certificates
- A **lab certificate authority** (P-384) with templates, computer and user auto-enrollment, SCEP and EST, revocation and CRLs, and an RSA chain for devices that need one
- A **P-384 chain** for WPA3-Enterprise 192-bit, created when you first need it
- A certificate **converter** (PEM, DER, PKCS#12, PKCS#7, JKS)

## Build from source

```sh
Scripts/make-app.sh          # builds build/LabDC.app
swift build -c release       # or just the command-line tools: labdc, labdc-kdc
```

Requires Xcode 26 / Swift 6.

## License

MIT — see [LICENSE](LICENSE).
