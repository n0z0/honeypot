# honeypot
NMAP Scanner Catcher


```ps
# Nyalakan logging untuk allowed & blocked + set lokasi & ukuran log
Set-NetFirewallProfile -LogAllowed True -LogBlocked True `
  -LogFileName 'pfirewall.log' `
  -LogMaxSizeKilobytes 32768

# Lihat live untuk verifikasi (opsional)
Get-Content 'pfirewall.log' -Wait
```
