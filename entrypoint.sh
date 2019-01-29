#!/bin/sh
set -ae

if [[ ${SECRETS_PATH} ]]; then
  for i in $(ls -d ${SECRETS_PATH}/*); do
    source $i
  done
fi

./traefik-forward-auth
