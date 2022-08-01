#!/bin/bash

cert=`ls *-cert*`
priv=`ls *-priv*`
sed -z 's/\n/\\n/g;s/^/export CLIENT_CERTIFICATE_PEM=\"/;s/\(export CLIENT_CERT.*\)\\n$/\1\"\n/' $cert > cert.str
sed -z 's/\n/\\n/g;s/^/export CLIENT_PRIVATE_KEY_PEM=\"/;s/\(export CLIENT_PRIV.*\)\\n$/\1\"\n/' $priv > priv.str
cat cert.str >> secrets.txt
cat priv.str >> secrets.txt
