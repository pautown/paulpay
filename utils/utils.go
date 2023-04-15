package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

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
}

type Response struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Result  struct {
		Transfers []Transfer `json:"transfers"`
	} `json:"result"`
}

func GetEth(eth_address string) ([]Transfer, error) {
	// Read Alchemy API KEY from file
	alchemyAPIKEY, err := ioutil.ReadFile("./alchemy_api")
	if err != nil {
		return nil, err
	}

	url := "https://eth-mainnet.g.alchemy.com/v2/" + string(alchemyAPIKEY)
	url = strings.ReplaceAll(url, "\n", "")

	payload := strings.NewReader("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"alchemy_getAssetTransfers\",\"params\":[{\"fromBlock\":\"0x0\",\"toBlock\":\"latest\",\"toAddress\":\"" + eth_address + "\",\"category\":[\"external\", \"erc20\"],\"withMetadata\":false,\"excludeZeroValue\":true,\"maxCount\":\"0x3e8\",\"order\":\"desc\"}]}")

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	transfers := response.Result.Transfers
	//var result []Transfer
	/*for i, transfer := range transfers {
		if transfer.Category != "internal" {
			fmt.Println("TX %.18f", i)
			asset := ""
			if transfer.RawContract.Address == "" {
				asset = "ETH"
			} else {
				asset = GetTokenName(transfer.RawContract.Address)
			}
			valueStr := fmt.Sprintf("%.18f", transfer.Value)
			//fmt.Printf("ASSET: %-10s AMT: %30s\n------------------------\n", asset, valueStr)
		}
	}*/

	return transfers, nil
}

var contracts = map[string]string{
	"PAINT":     "0x4c6ec08cf3fc987c6c4beb03184d335a2dfc4042",
	"HEX":       "0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39",
	"MATIC":     "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0",
	"BUSD":      "0x4Fabb145d64652a948d72533023f6E7A623C7C53",
	"SHIBA_INU": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
	"USDC":      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
	"TETHER":    "0xdac17f958d2ee523a2206206994597c13d831ec7",
	"WBTC":      "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
	"PNK":       "0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d",
}

var cryptoMap = map[string]map[string]string{
	"paint": {
		"name":     "Paint",
		"code":     "PAINT",
		"svg":      "paint.svg",
		"min":      "{{.MinPaint}}",
		"contract": contracts["PAINT"],
	},
	"hex": {
		"name":     "Hexcoin",
		"code":     "HEX",
		"svg":      "hex.svg",
		"min":      "{{.MinHex}}",
		"contract": contracts["HEX"],
	},
	"matic": {
		"name":     "Polygon",
		"code":     "MATIC",
		"svg":      "matic.svg",
		"min":      "{{.MinPolygon}}",
		"contract": contracts["MATIC"],
	},
	"busd": {
		"name":     "Binance USD",
		"code":     "BUSD",
		"svg":      "busd.svg",
		"min":      "{{.MinBusd}}",
		"contract": contracts["BUSD"],
	},
	"shiba_inu": {
		"name":     "Shiba Inu",
		"code":     "SHIB",
		"svg":      "shiba_inu.svg",
		"min":      "{{.MinShib}}",
		"contract": contracts["SHIBA_INU"],
	},
	"usdc": {
		"name":     "USD Coin",
		"code":     "USDC",
		"svg":      "usdc.svg",
		"min":      "{{.MinUsdc}}",
		"contract": contracts["USDC"],
	},
	"tether": {
		"name":     "Tether",
		"code":     "TUSD",
		"svg":      "tether.svg",
		"min":      "{{.MinTusd}}",
		"contract": contracts["TETHER"],
	},
	"wbtc": {
		"name":     "Wrapped Bitcoin",
		"code":     "WBTC",
		"svg":      "wbtc.svg",
		"min":      "{{.MinWbtc}}",
		"contract": contracts["WBTC"],
	},
	"pnk": {
		"name":     "Kleros",
		"code":     "PNK",
		"svg":      "pnk.svg",
		"min":      "{{.MinPnk}}",
		"contract": contracts["PNK"],
	},
}

func GetTransactionAmount(t Transfer) float64 {
	return t.Value
}

func GetTransactionToken(t Transfer) string {
	asset := ""
	if t.RawContract.Address == "" {
		asset = "ETH"
	} else {
		asset = GetTokenName(t.RawContract.Address)
	}
	return asset
}

func GetTokenName(contractAddr string) string {
	switch contractAddr {
	case contracts["PAINT"]:
		return "PAINT"
	case contracts["HEX"]:
		return "HEX"
	case contracts["MATIC"]:
		return "MATIC"
	case contracts["BUSD"]:
		return "BUSD"
	case contracts["SHIBA_INU"]:
		return "SHIBA_INU"
	case contracts["USDC"]:
		return "USDC"
	case contracts["TETHER"]:
		return "TETHER"
	case contracts["WBTC"]:
		return "WBTC"
	case contracts["PNK"]:
		return "PNK"
	default:
		return "UNKNOWN"
	}
}

func GetCryptoContractByCode(code string) (string, error) {
	code = strings.ToUpper(code)
	for _, cryptoInfo := range cryptoMap {
		if cryptoInfo["code"] == code {
			return cryptoInfo["contract"], nil
		}
	}
	return "", fmt.Errorf("crypto with code %s not found", code)
}

func CheckDonos(transfers []Transfer, pending_donos []SuperChat) []SuperChat {
	var completed_donos []SuperChat
	for i, pending_dono := range pending_donos {
		if !pending_dono.Completed {
			for _, transfer := range transfers {
				log.Println("Transfer value:", transfer.Value)
				log.Println("Needed amount:", pending_dono.AmountNeeded)
				if isEqual(transfer.Value, pending_dono.AmountNeeded) {
					pending_donos[i].Completed = true
					pending_donos[i].CheckedAt = time.Now().String()
					completed_donos = append(completed_donos, pending_donos[i])
					log.Printf("Completed donation from %v for %.18f ETH", transfer.From, transfer.Value)
				}
			}
		}
	}

	fmt.Println("Completed Donations:")
	for _, dono := range completed_donos {
		fmt.Printf("Amount: %.18f %v, Completed: %v, Checked At: %v\n", dono.CryptoCode, dono.AmountNeeded, dono.Completed, dono.CheckedAt)
	}

	return completed_donos
}

func CreatePendingDono(name string, message string, mediaURL string, amountNeeded float64, cryptoCode string) SuperChat {
	amountNeeded = FuzzDono(amountNeeded)
	pendingDono := SuperChat{
		Name:         name,
		Message:      message,
		MediaURL:     mediaURL,
		AmountNeeded: amountNeeded,
		Completed:    false,
		CreatedAt:    time.Now().String(),
		CheckedAt:    time.Now().String(),
		CryptoCode:   cryptoCode,
	}
	return pendingDono
}

func FuzzDono(ethAmount float64) float64 {
	// generate random value between 0 and 100 billionth
	rand.Seed(time.Now().UnixNano())
	randVal := rand.Float64() / 10000000.0

	// add random value to input amount
	newAmount := ethAmount + randVal

	return newAmount
}

func AppendPendingDono(pending_donos []SuperChat, new_dono SuperChat) []SuperChat {
	pending_donos = append(pending_donos, new_dono)
	return pending_donos
}

func CheckMatchingDono(amount float64, cryptoCode string, pending_donos []SuperChat) bool {
	for _, potential_dono := range pending_donos {
		if potential_dono.AmountNeeded == amount && potential_dono.CryptoCode == cryptoCode {
			return true
		}
	}
	return false
}

func isEqual(a, b float64) bool {
	const epsilon = 1e-18 // threshold for difference
	return math.Abs(a-b) < epsilon
}

func IsEqual(a, b float64) bool {
	const epsilon = 1e-18 // threshold for difference
	return math.Abs(a-b) < epsilon
}
