cnffile="admin.cnf"
reqfile="admin.req"
keyfile="admin.key"

dn="/DC=htb/DC=windcorp/CN=Users/CN=Administrator"

cat > $cnffile <<EOF
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@windcorp.htb

EOF

openssl req -config $cnffile -subj $dn -new -nodes -sha256 -out $reqfile -keyout $keyfile
