#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the 'demo' directory." >&2
  exit 1
fi

echo "WARNING: This will run 'killall redoctober pald demo'; press enter to continue or ctrl+C to abort."
read line

killall redoctober pald demo
rm -rf tmp/sock/* # this is actually in /tmp somewhere
rm -rf tmp/*
