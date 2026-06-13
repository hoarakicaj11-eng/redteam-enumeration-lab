# PC Health Scanner v6.0

A Windows security scanner with port scanning, firewall checks, RDP/account
hardening, ClamAV virus scanning, USB malware scanning, patch history, and
report generation.

## Requirements
- Windows 7/8/10/11
- Python 3.8+
- (Optional) [ClamAV for Windows](https://www.clamav.net/downloads) for virus scanning

## Install & Run

```bash
git clone https://github.com/<your-username>/pc-health-scanner.git
cd pc-health-scanner
pip install -r requirements.txt
python pc_health_scanner.py
```

For full functionality (firewall rules, disabling RDP/accounts, port blocking),
run your terminal **as Administrator**.

## Features
- Port scanning with one-click firewall block
- Firewall status check + enable
- RDP detection + disable
- User account listing + disable
- Suspicious external connection detection + block
- USB drive malware scanning (ClamAV or built-in hash check)
- ClamAV scan, update, quarantine, and delete
- Windows patch history
- Save full text report
- Desktop shortcut creation
