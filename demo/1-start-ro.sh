#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

redoctober -addr=localhost:8080 \
                   -vaultpath=tmp/diskrecord.json \
                   -certs=certs/client.pem \
                   -keys=certs/client-key.pem &

# Give RO server a chance to begin listening
sleep 1

# Creating the disk vault only happens once and so isn't part of the client library
curl --cacert certs/ca.pem https://localhost:8080/create -d '{"Name":"demo","Password":"demo"}'
# Provisioning users is usually done via the UI; we script it here for convenience (using highly secure passwords, of course)
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"jackryan","Password":"0000"}'
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"markoramius","Password":"password1"}'
# In PAL, machines are also Red October users
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"demo_machine","Password":"demo_machine"}'
