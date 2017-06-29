#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

RO_USER=demo
RO_PASS=demo

SECRET1=`echo "Defect at Dawn."|base64`
SECRET2=`echo "One ping only."|base64`

CT1=`curl -s --cacert certs/ca.pem https://localhost:8080/encrypt -d '{"Name":"demo","Password":"demo","Minimum":2,"Owners":["jackryan","markoramius"],"Labels":["demo"],"Data":"'$SECRET1'"}'|jq -r .Response`
CT2=`curl -s --cacert certs/ca.pem https://localhost:8080/encrypt -d '{"Name":"demo","Password":"demo","Minimum":2,"Owners":["jackryan","markoramius"],"Labels":["demo"],"Data":"'$SECRET2'"}'|jq -r .Response`

cat << EOF > tmp/pal_secrets.yaml
demo:
  env:
    SECRET: "ro:$CT1"
  file:
    /tmp/secret.txt: "ro:$CT2"
EOF

echo "Encrypted secrets and wrote them to tmp/pal_secrets.yaml:"
cat tmp/pal_secrets.yaml
