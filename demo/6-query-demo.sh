#!/bin/bash

# not technically necessary, but be consistent with other scripts
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

# We interrogate our demonstration server
curl localhost:9090/secrets
