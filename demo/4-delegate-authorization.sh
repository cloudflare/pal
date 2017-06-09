#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

# Red October can only decrypt a ciphertext when enough
# "owners" of that ciphertext (chosen at encryption time)
# have "delegated" their authority to the server.
#
# Delegations may limit the number of times they are used,
# the users who may consume them, and the length of time
# for which they are valid.
#
# PAL also uses Red October's labeling mechanism so that
# owners may own different secrets in different services
# and authorize them independently.

curl --cacert certs/ca.pem https://localhost:8080/delegate -d '{"Name":"jackryan","Password":"0000","Uses":10,"Time":"1h","Users":["demo_machine"],"Labels":["demo"]}'
curl --cacert certs/ca.pem https://localhost:8080/delegate -d '{"Name":"markoramius","Password":"password1","Uses":10,"Time":"1h","Users":["demo_machine"],"Labels":["demo"]}'
