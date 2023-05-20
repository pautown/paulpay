#!/bin/bash

portStr="RPC_PORT"
user_id="USER_ID"

curl -X POST http://localhost:"$portStr"/json_rpc \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": "0",
    "method": "open_wallet",
    "params": {
      "filename": "users/'"$user_id"'/monero/wallet",
      "password": ""
    }
  }'