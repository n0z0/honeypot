# honeypot
NMAP Scanner Catcher


```ps
# cek status log
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogFileName

# Nyalakan logging untuk allowed & blocked + set lokasi & ukuran log
Set-NetFirewallProfile -LogAllowed True -LogBlocked True `
  -LogFileName 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' `
  -LogMaxSizeKilobytes 32767

# Lihat live untuk verifikasi (opsional)
Get-Content 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' -Wait
```
