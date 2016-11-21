#!/bin/bash -e

PW="$(python -c "import os; print os.urandom(256).encode('hex')")"
echo $PW| sha256sum
curl --cacert /home/jkroll/cf-repos/cacert.pem -d '{"Name":"ro2.ro.cfdata.org Admin","Password":"'$PW'"}' https://ro2.ro.cfdata.org/create
echo $PW | gpg --armor --encrypt -r 25F2C005 -r 4D209CCC

