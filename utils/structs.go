package utils

import (
	"crypto/ed25519"
	"math/big"
	"time"
)

type ETHCheckAddress struct {
	ETHstr   string
	ERC20str string
}

type InviteCode struct {
	Value  string
	Active bool
}

type CryptoSuperChat struct {
	Name            string
	Message         string
	Media           string
	Amount          string
	Address         string
	QRB64           string
	PayID           string
	CheckURL        string
	Currency        string
	DonationID      int64
	ContractAddress string
	WeiAmount       *big.Int
}

type SuperChat struct {
	Name         string
	Message      string
	Address      string
	MediaURL     string
	AmountNeeded float64
	Completed    bool
	CreatedAt    string
	CheckedAt    string
	CryptoCode   string
	EncryptedIP  string
}

type Donation struct {
	ID              string `json:"donoID"`
	DonationName    string `json:"donationName"`
	DonationMessage string `json:"donationMessage"`
	DonationMedia   string `json:"donationMedia"`
	USDValue        string `json:"usdValue"`
	AmountSent      string `json:"amountSent"`
	Crypto          string `json:"crypto"`
}

type User struct {
	UserID               int
	Username             string
	HashedPassword       []byte
	EthAddress           string
	SolAddress           string
	HexcoinAddress       string
	XMRWalletPassword    string
	MinDono              int
	MinMediaDono         int
	MediaEnabled         bool
	CreationDatetime     string
	ModificationDatetime string
	Links                string
	DonoGIF              string
	DonoSound            string
	AlertURL             string
	MinSol               float64
	MinEth               float64
	MinXmr               float64
	MinPaint             float64
	MinHex               float64
	MinMatic             float64
	MinBusd              float64
	MinShib              float64
	MinUsdc              float64
	MinTusd              float64
	MinWbtc              float64
	MinPnk               float64
	DateEnabled          time.Time
	WalletUploaded       bool
	WalletPending        bool
	CryptosEnabled       CryptosEnabled
	BillingData          BillingData
	DefaultCrypto        string
}

type RawContract struct {
	Value   string `json:"value"`
	Address string `json:"address"`
	Decimal string `json:"decimal"`
}

type Transfer struct {
	BlockNum        string      `json:"blockNum"`
	UniqueId        string      `json:"uniqueId"`
	Hash            string      `json:"hash"`
	From            string      `json:"from"`
	To              string      `json:"to"`
	Value           float64     `json:"value"`
	Erc721TokenId   interface{} `json:"erc721TokenId"`
	Erc1155Metadata interface{} `json:"erc1155Metadata"`
	TokenId         interface{} `json:"tokenId"`
	Asset           string      `json:"asset"`
	Category        string      `json:"category"`
	RawContract     RawContract `json:"rawContract"`
}

type Response struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Result  struct {
		Transfers []Transfer `json:"transfers"`
	} `json:"result"`
}

type PriceData struct {
	Monero struct {
		Usd float64 `json:"usd"`
	} `json:"monero"`
	Solana struct {
		Usd float64 `json:"usd"`
	} `json:"solana"`
	Ethereum struct {
		Usd float64 `json:"usd"`
	} `json:"ethereum"`
}

type Link struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

type CryptoData struct {
	CryptoCode string `json:"cryptocode"`
	Enabled    bool   `json:"enabled"`
}

type CryptosEnabled struct {
	XMR   bool
	SOL   bool
	ETH   bool
	PAINT bool
	HEX   bool
	MATIC bool
	BUSD  bool
	SHIB  bool
	PNK   bool
}

type CryptoPrice struct {
	Monero     float64 `json:"monero"`
	Solana     float64 `json:"solana"`
	Ethereum   float64 `json:"ethereum"`
	Paint      float64 `json:"paint"`
	Hexcoin    float64 `json:"hex"`
	Polygon    float64 `json:"matic"`
	BinanceUSD float64 `json:"binance-usd"`
	ShibaInu   float64 `json:"shiba-inu"`
	Kleros     float64 `json:"pnk"`
	WBTC       float64 `json:"wbtc"`
	TUSD       float64 `json: "tusd"`
}

type UserPageData struct {
	ErrorMessage string
}

type PendingUser struct {
	ID             int
	Username       string
	HashedPassword []byte
	XMRPayID       string
	ETHNeeded      string
	XMRNeeded      string
	ETHAddress     string
	XMRAddress     string
}

type GetBalanceResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value uint64 `json:"value"`
	} `json:"result"`
	ID int `json:"id"`
}

type BillingData struct {
	BillingID       int
	UserID          int
	AmountThisMonth float64
	AmountTotal     float64
	AmountNeeded    float64
	ETHAmount       string
	XMRAmount       string
	XMRPayID        string
	XMRAddress      string
	Enabled         bool
	NeedToPay       bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type IndexDisplay struct {
	MaxChar        int
	MinDono        int
	MinSolana      float64
	MinMonero      float64
	MinEthereum    float64
	MinPaint       float64
	MinHex         float64
	MinPolygon     float64
	MinBusd        float64
	MinShib        float64
	MinPnk         float64
	SolPrice       float64
	XMRPrice       float64
	ETHPrice       float64
	PaintPrice     float64
	HexPrice       float64
	PolygonPrice   float64
	BusdPrice      float64
	ShibPrice      float64
	PnkPrice       float64
	MinAmnt        float64
	WalletPending  bool
	Links          string
	Checked        string
	CryptosEnabled CryptosEnabled
	DefaultCrypto  string
	Username       string
}

type AlertPageData struct {
	Name          string
	Message       string
	Amount        float64
	Currency      string
	MediaURL      string
	USDAmount     float64
	Refresh       int
	DisplayToggle string
	Userpath      string
}

type ProgressbarData struct {
	Message string
	Needed  float64
	Sent    float64
	Refresh int
}

type AccountPayData struct {
	Username    string
	AmountXMR   string
	AmountETH   string
	AddressXMR  string
	AddressETH  string
	QRB64XMR    string
	QRB64ETH    string
	UserID      int
	BillingData BillingData
	DateCreated time.Time
}

type OBSDataStruct struct {
	Username    string
	FilenameGIF string
	FilenameMP3 string
	URLdisplay  string
	URLdonobar  string
	Message     string
	Needed      float64
	Sent        float64
}

type RPCResponse struct {
	ID      string `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		IntegratedAddress string `json:"integrated_address"`
		PaymentID         string `json:"payment_id"`
	} `json:"result"`
}

type AddressSolana struct {
	KeyPublic  string
	KeyPrivate ed25519.PrivateKey
	DonoName   string
	DonoString string
	DonoAmount float64
	DonoAnon   bool
}

type MoneroPrice struct {
	Monero struct {
		Usd float64 `json:"usd"`
	} `json:"monero"`
}

// Add the following struct to store the incoming data
type UpdateCryptosRequest struct {
	UserID          string          `json:"userId"`
	SelectedCryptos map[string]bool `json:"selectedCryptos"`
}

type ViewDonosData struct {
	Username string
	Donos    []Dono
}

type Dono struct {
	ID           int
	UserID       int
	Address      string
	Name         string
	Message      string
	AmountToSend string
	AmountSent   string
	CurrencyType string
	AnonDono     bool
	Fulfilled    bool
	EncryptedIP  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	USDAmount    float64
	MediaURL     string
}
