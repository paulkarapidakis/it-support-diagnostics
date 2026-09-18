# IT Support Diagnostics

A PowerShell tool I built to practice Windows and network troubleshooting while automating common first-line IT support checks.

## What it checks

* Windows, CPU, memory, and disk information
* system uptime and pending restart
* network adapters and IPv4 addresses
* DHCP / static IP configuration
* APIPA addresses
* DNS servers and DNS resolution
* default gateway
* gateway and internet reachability
* basic latency
* Wi-Fi information
* selected Windows services
* Microsoft Defender
* BitLocker status

Results are shown as they complete using `OK`, `INFO`, `WARNING`, and `CRITICAL`.
