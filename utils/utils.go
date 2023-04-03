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

type Transfer struct {
	BlockNum         string  `json:"blockNum"`
	UniqueId         string  `json:"uniqueId"`
	Hash             string  `json:"hash"`
	From             string  `json:"from"`
	To               string  `json:"to"`
	Value            float64 `json:"value"`
	Erc721TokenId    string  `json:"erc721TokenId"`
	Erc1155Metadata  string  `json:"erc1155Metadata"`
	TokenId          string  `json:"tokenId"`
	Asset            string  `json:"asset"`
	Category         string  `json:"category"`
	RawContractValue string  `json:"rawContract.value"`
	RawContractAddr  string  `json:"rawContract.address"`
	RawContractDec   string  `json:"rawContract.decimal"`
}

type EthSuperChat struct {
	Name         string
	Message      string
	Address      string
	MediaURL     string
	AmountNeeded float64
	Completed    bool
	CreatedAt    string
	CheckedAt    string
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

	payload := strings.NewReader("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"alchemy_getAssetTransfers\",\"params\":[{\"fromBlock\":\"0x0\",\"toBlock\":\"latest\",\"toAddress\":\"" + eth_address + "\",\"category\":[\"external\"],\"withMetadata\":false,\"excludeZeroValue\":true,\"maxCount\":\"0x3e8\",\"order\":\"desc\"}]}")

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
	var result []Transfer
	for _, transfer := range transfers {
		if transfer.Category != "internal" {
			fmt.Println("From address:", transfer.From)
			fmt.Println("To address:", transfer.To)
			fmt.Println("Asset:", transfer.Asset)
			fmt.Printf("Value: %.18f\n", transfer.Value)
			fmt.Println("-----")
		}
	}
	return result, nil
}

func CheckEthDonos(transfers []Transfer, pending_donos []EthSuperChat) []EthSuperChat {
	var completed_donos []EthSuperChat
	for i, pending_dono := range pending_donos {
		if !pending_dono.Completed {
			for _, transfer := range transfers {
				if isEqual(transfer.Value, pending_dono.AmountNeeded) {
					pending_donos[i].Completed = true
					pending_donos[i].CheckedAt = time.Now().String()
					completed_donos = append(completed_donos, pending_donos[i])
					log.Printf("Completed donation from %v for %.18f ETH", transfer.From, transfer.Value)
				}
			}
		}
	}
	return completed_donos
}

func CreatePendingDono(name string, message string, mediaURL string, amountNeeded float64) EthSuperChat {
	amountNeeded = FuzzDono(amountNeeded)
	pendingDono := EthSuperChat{
		Name:         name,
		Message:      message,
		MediaURL:     mediaURL,
		AmountNeeded: amountNeeded,
		Completed:    false,
		CreatedAt:    time.Now().String(),
		CheckedAt:    time.Now().String(),
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

func AppendPendingDono(pending_donos []EthSuperChat, new_dono EthSuperChat) []EthSuperChat {
	pending_donos = append(pending_donos, new_dono)
	return pending_donos
}

func RemoveCompletedDonos(pending_donos []EthSuperChat) []EthSuperChat {
	var updated_donos []EthSuperChat

	for _, dono := range pending_donos {
		if !dono.Completed {
			updated_donos = append(updated_donos, dono)
		}
	}

	return updated_donos
}

func isEqual(a, b float64) bool {
	const epsilon = 1e-18 // threshold for difference
	return math.Abs(a-b) < epsilon
}
