# OSCP Cheatsheet

* [Enumeration](#Enumeration)
* [Fuzzing](#Fuzzing)
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

# SQL Injection

## Error Based SQL Injection

~~~ sql
-- MSSQL
if (@@VERSION)=9 select 1 else select 2;
~~~
