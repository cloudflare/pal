#!/bin/bash

# NOTE: This script is meant to be run by 'make', which is run from the
# repository root.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd .. && pwd )"
if [ "$DIR" != "$(pwd)" ]; then
  echo "Please run this script while cd'd to the repository root." >&2
  exit 1
fi

cd test

#########
# Setup #
#########

cat << EOF

Setup
=====
EOF

# make sure tmp exists and is empty
mkdir -p tmp || exit 1
rm -rf tmp/*

docker-compose create

#################
# Initialize RO #
#################

cat << EOF

Initialize RO
=============
EOF

docker-compose up -d redoctober

# Give RO a chance to begin listening
sleep 2

# Create the admin user
echo 'Creating admin user "demo"'
curl --cacert certs/ca.pem https://localhost:8080/create -d '{"Name":"demo","Password":"demo"}'
# Create the non-admin users
echo; echo 'Creating user "jackryan"'
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"jackryan","Password":"0000"}'
echo; echo 'Creating user "markoramius"'
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"markoramius","Password":"password1"}'
echo; echo 'Creating user "demo_machine"'
curl --cacert certs/ca.pem https://localhost:8080/create-user -d '{"Name":"demo_machine","Password":"demo_machine"}'
echo

######################
# Initialize Secrets #
######################

cat << EOF

Initialize Secrets
==================
EOF

RO_USER=demo
RO_PASS=demo

SECRET1=`echo -n "Defect at Dawn."|base64`
SECRET2=`echo -n "One ping only."|base64`

echo 'Encrypting SECRET1: "Defect at dawn."'
CT1=`curl -s --cacert certs/ca.pem https://localhost:8080/encrypt -d '{"Name":"demo","Password":"demo","Minimum":2,"Owners":["jackryan","markoramius"],"Labels":["demo"],"Data":"'$SECRET1'"}'|jq -r .Response`
echo 'Encrypting SECRET2: "One ping only."'
CT2=`curl -s --cacert certs/ca.pem https://localhost:8080/encrypt -d '{"Name":"demo","Password":"demo","Minimum":2,"Owners":["jackryan","markoramius"],"Labels":["demo"],"Data":"'$SECRET2'"}'|jq -r .Response`

cat << EOF > tmp/pal_secrets.yaml
demo:
  env:
    SECRET: "ro:$CT1"
  file:
    /tmp/secret.txt: "ro:$CT2"
EOF

##############
# Start pald #
##############

cat << EOF

Initialize pald
===============
EOF

docker-compose up -d pald

##########################
# Delegate Authorization #
##########################

cat << EOF

Initialize Authorization
========================
EOF

echo 'Delegating SECRET1'
curl --cacert certs/ca.pem https://localhost:8080/delegate -d '{"Name":"jackryan","Password":"0000","Uses":10,"Time":"1h","Users":["demo_machine"],"Labels":["demo"]}'
echo; echo 'Delegating SECRET1'
curl --cacert certs/ca.pem https://localhost:8080/delegate -d '{"Name":"markoramius","Password":"password1","Uses":10,"Time":"1h","Users":["demo_machine"],"Labels":["demo"]}'
echo

###########
# Run pal #
###########

cat << EOF

Run Client Container
====================
EOF

echo 'Running pal to decrypt and verify secrets...'
docker-compose run -e PAL_SECRETS_YAML="$(cat tmp/pal_secrets.yaml)" pal

###########
# Cleanup #
###########

cat << EOF

Cleanup
=======
EOF

docker-compose down
rm -rf tmp
