# PayPaul

- Self-hosted, noncustodial crypto-currency (currently Monero(XMR) and Solana(SOL)) superchat system written in Go.
- Provides notifications and a progress bar usable in OBS as well as admin pages for settings like minimum donos.
- Settings pages /user /userobs (default login is user:admin password:hunter123)

To see a working instance of PayPaul, see [pay.paul.town](https://pay.paul.town).

# Installation

1. ```apt install golang```
2. ```git clone https://github.com/pautown/paulpay.git```
3. ```cd shadowchat```
4. ```go install github.com/skip2/go-qrcode@latest``'
5. ```go run main.go```

A webserver at 127.0.0.1:8900 is running.

This is currently designed to be run on a cloud server with nginx proxypass for TLS.

# Monero Wallet Setup (needs to be rewritten.)

1. Generate a view only wallet using the `monero-wallet-gui` from getmonero.org. Preferably with no password (need to change code if you have a password)
2. Copy the newly generated `walletname_viewonly` and `walletname_viewonly.keys` files to your VPS as 'wallet' and 'wallet.keys'
3. Download the `monero-wallet-rpc` binary that is bundled with the getmonero.org wallets.
4. Place the 'monero-wallet-rpc' inside monero folder
5. Change code inside main.go to reflect what file extension monero-wallet-rpc is. This is being developed on windows so it has .exe in the start monero func but for linux (most server environments) it won't have the .exe file extension so remove that.

# Usage
- Visit 127.0.0.1:8900/user to view your user settings
- Visit 127.0.0.1:8900/userobs to view your user OBS settings
- Visit 127.0.0.1:8900/alert to see notifications (only have one of these open at a time, preferrably in the OBS screen)
- Visit 127.0.0.1:8900/progressbar to see the OBS progressbar which gets modified in the OBS settings url
- The default username is `admin` and password `hunter123`. Change these in the http://127.0.0.1:8900/user panel

# OBS
- Add a Browser source in OBS and point it to `127.0.0.1:8900/alert` for Dono Alerts
- Add a Browser source in OBS and point it to `127.0.0.1:8900/progressbar` to display the Dono Bar in OBS

# Future plans
- Youtube Media Links
- Sound and GIF for dono
- TTS integration for donos
- Eth donations using batch transaction processing
- Hex donations using batch transaction processing
- API integration for getting Powerchat and Streamlabs Donos and keeping track of USD value
- Selection of which dono methods are available



# License
GPLv3

### Origin
This comes from [https://git.sr.ht/~anon_/shadowchat](https://git.sr.ht/~anon_/shadowchat) and the base logic (mostly rewritten now) is not Paul's original
work, although without the base logic I would have never started doing this, so thank you to the great mind behind this.

### Donate

To support further development of this project, send XMR to me (Paul) at:
`88K988HXHBTZZEFACejzJRDe7zMiKviesFKWtq4Q3Bo6VZfPZDWFzbod4Kn7SudVSBKhu5GqMUqBUXFNj5wBLyWuNWe4nqN`
