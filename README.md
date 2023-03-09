# PayPaul

- Self-hosted, noncustodial crypto-currency (currently Monero(XMR) and Solana(SOL)) superchat system written in Go.
- Provides notifications and a progress bar usable in OBS as well as admin pages for settings like minimum donos.

To see a working instance of PayPaul, see [pay.paul.town](https://pay.paul.town).

# Installation

1. ```apt install golang```
2. ```git clone https://git.sr.ht/~anon_/shadowchat```
3. ```cd shadowchat```
4. ```go install github.com/skip2/go-qrcode@latest```
5. edit ```config.json```
6. ```go run main.go```

A webserver at 127.0.0.1:8900 is running. Pressing the pay button will result in a 500 Error if the `monero-wallet-rpc`
is not running.
This is designed to be run on a cloud server with nginx proxypass for TLS.

# Monero Setup

1. Generate a view only wallet using the `monero-wallet-gui` from getmonero.org. Preferably with no password
2. Copy the newly generated `walletname_viewonly` and `walletname_viewonly.keys` files to your VPS
3. Download the `monero-wallet-rpc` binary that is bundled with the getmonero.org wallets.
4. Start the RPC
   wallet: `monero-wallet-rpc --rpc-bind-port 28088 --daemon-address https://xmr-node.cakewallet.com:18081 --wallet-file /opt/wallet/walletname_viewonly --disable-rpc-login --password ""`

# Usage

- Visit 127.0.0.1:8900/view to view your superchat history
- Visit 127.0.0.1:8900/alert?auth=adminadmin to see notifications
- The default username is `admin` and password `adminadmin`. Change these in `main.go`
- Edit web/index.html and web/style.css to customize your front page!

# OBS

- Add a Browser source in obs and point it to `https://example.com/alert?auth=adminadmin`

# Future plans

- Blocklist for naughty words
- Widget for OBS displaying top donators
- Settings page for on-the-fly changes (minimum donation amount, hide all amounts, etc.)

# License

GPLv3

### Origin

This comes from [https://git.sr.ht/~anon_/shadowchat](https://git.sr.ht/~anon_/shadowchat) and the base logic (mostly rewritten now) is not Paul's original
work.

### Donate

To support further development of this project, send XMR to me (Paul) at:
`88K988HXHBTZZEFACejzJRDe7zMiKviesFKWtq4Q3Bo6VZfPZDWFzbod4Kn7SudVSBKhu5GqMUqBUXFNj5wBLyWuNWe4nqN`
