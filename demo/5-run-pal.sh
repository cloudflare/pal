#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

# The second PAL tool is pal, a client binary that runs
# as a container entrypoint to decrypt secrets. pal is controlled
# primarily by environment variables, to allow containers to be
# repurposed in development, staging, and production environments.
#
# Ciphertexts themselves are provisioned in a YAML configuration
# format, exposed to the tool as an environment variable.

export PAL_SECRETS_YAML=`cat tmp/pal_secrets.yaml`
export APP_ENV="demo"

pal -socket tmp/sock/pald.sock -- ./demo &
