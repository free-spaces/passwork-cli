#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-default}"

PASSWORK_URL_DEFAULT="${PASSWORK_URL_DEFAULT:-https://passwork.example.com}"
PASSWORK_ACCESS_TOKEN_DEFAULT="${PASSWORK_ACCESS_TOKEN_DEFAULT:-CHANGE_ME_DEFAULT_TOKEN}"

PASSWORK_URL_CSE="${PASSWORK_URL_CSE:-https://prod.pwk.com}"
PASSWORK_ACCESS_TOKEN_CSE="${PASSWORK_ACCESS_TOKEN_CSE:-CHANGE_ME_CSE_TOKEN}"
PASSWORK_MASTER_KEY_CSE="${PASSWORK_MASTER_KEY_CSE:-CHANGE_ME_CSE_MASTER_KEY}"

kubectl -n "$NAMESPACE" create secret generic passwork-default-env \
  --from-literal=PASSWORK_URL="$PASSWORK_URL_DEFAULT" \
  --from-literal=PASSWORK_ACCESS_TOKEN="$PASSWORK_ACCESS_TOKEN_DEFAULT" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic passwork-cse-env \
  --from-literal=PASSWORK_URL="$PASSWORK_URL_CSE" \
  --from-literal=PASSWORK_ACCESS_TOKEN="$PASSWORK_ACCESS_TOKEN_CSE" \
  --from-literal=PASSWORK_MASTER_KEY="$PASSWORK_MASTER_KEY_CSE" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secrets applied in namespace: $NAMESPACE"
