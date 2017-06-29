#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

# make sure tmp exists and is empty
mkdir -p tmp || exit 1
rm -rf tmp/*
# create temp directory in /tmp for pald unix socket
TMP=$(mktemp -d)
ln -s "$TMP" tmp/sock

HAVE_ALL_DEPS="true"
which redoctober >/dev/null || { echo "could not find 'redoctober' in PATH"; HAVE_ALL_DEPS="false"; }
which pal >/dev/null || { echo "could not find 'pal' in PATH"; HAVE_ALL_DEPS="false"; }
which pald >/dev/null || { echo "could not find 'pald' in PATH"; HAVE_ALL_DEPS="false"; }
which go >/dev/null || { echo "could not find 'go' in PATH"; HAVE_ALL_DEPS="false"; }

if [ "$HAVE_ALL_DEPS" == "false" ]; then
  echo "Please install dependencies before continuing." >&2
  exit 1
else
  echo "Dependencies successfully verified."
fi

echo "Building demo ('go build') ..."
go build -o demo
