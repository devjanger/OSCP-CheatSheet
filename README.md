# OSCP Cheatsheet

* [Enumeration](#Enumeration)
* [Fuzzing](#Fuzzing)
* [SNMP - 161](#snmp---161)
* [RDP - 3389](#rdp---3389)

# Enumeration

## Nmap Initial scan

~~~ bash
nmap -sSCV -Pn $target
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

