#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

# PAL consists of two main components: a server and a client.
# The server (pald) runs outside any container, on every cluster node.
# Ordinarily, we run it under systemd and use socket activation
# for resilience, though we've not observed an outage of pald in >6mo
# of operation.

# -host configures where to open a Unix socket. This socket
#   would ordinarily be mounted into containers using the Docker
#   "volumes" directive.
# -config is the location of the server's configuration,
#   containing machine credentials for interacting with Red October
# -env allows the same server config file to contain multiple
#   environments. We only have one here.

pald -addr.rpc unix://tmp/sock/pald.sock -config config.yaml -env demo &
