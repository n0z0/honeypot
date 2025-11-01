# honeypot

```ps
 Get-NetAdapter | Select Name, InterfaceDescription, InterfaceGuid, ifIndex, Status

.\synwatcher.exe -iface "\Device\NPF_{A91E7D86-E24B-4761-94EF-DE993C6116BD}"
```

NMAP Scanner Catcher

```ps
# cek status log
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogFileName

# Nyalakan logging untuk allowed & blocked + set lokasi & ukuran log
Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 32767

Set-NetFirewallProfile -LogAllowed False -LogBlocked False -LogIgnored False -LogFileName 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 32767

# Lihat live untuk verifikasi (opsional)
Get-Content 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' -Wait
```
