#!/bin/bash

FAILED="false"
if [ "${SECRET}" != "Defect at Dawn." ]; then
  echo "Unexpected value for secret SECRET: got \"${SECRET}\"; want \"Defect at Dawn.\"" >&2
  FAILED="true"
fi
SECRETTXT="$(cat /tmp/secret.txt)"
if [ "${SECRETTXT}" != "One ping only." ]; then
  echo "Unexecpted value for secret at /tmp/secret.txt: got \"${SECRETTXT}\"; want \"One ping only.\"" >&2
  FAILED="true"
fi

if [ "${FAILED}" == "true" ]; then
  exit 1
else
  echo "Secrets verified!"
fi
