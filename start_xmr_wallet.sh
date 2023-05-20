#!/bin/bash

daemon_address="https://xmr-node.cakewallet.com:18081"
rpc_bind_port=$1
wallet_file="users/$2/monero/wallet"

monero/monero-wallet-rpc \
  --rpc-bind-port "$rpc_bind_port" \
  --daemon-address "$daemon_address" \
  --wallet-file "$wallet_file" \
  --disable-rpc-login \
  --password ""



