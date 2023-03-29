package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"strings"
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

type Response struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Result  struct {
		Transfers []Transfer `json:"transfers"`
	} `json:"result"`
}

func GetEth(eth_address string) {
	// Read Alchemy API KEY from file
	alchemyAPIKEY, err := ioutil.ReadFile("./alchemy_api")
	if err != nil {
		log.Println(err)
	}
	url := "https://eth-mainnet.g.alchemy.com/v2/" + string(alchemyAPIKEY)

	payload := strings.NewReader("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"alchemy_getAssetTransfers\",\"params\":[{\"fromBlock\":\"0x0\",\"toBlock\":\"latest\",\"toAddress\":\"" + eth_address + "\",\"category\":[\"external\"],\"withMetadata\":false,\"excludeZeroValue\":true,\"maxCount\":\"0x3e8\",\"order\":\"desc\"}]}")

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing response:", err)
		return
	}

	transfers := response.Result.Transfers

	for _, transfer := range transfers {
		if transfer.Category != "internal" {
			fmt.Println("From address:", transfer.From)
			fmt.Println("To address:", transfer.To)
			fmt.Println("Asset:", transfer.Asset)
			fmt.Printf("Value: %.18f\n", transfer.Value)
			fmt.Println("-----")
		}
	}
}

func isEqual(a, b float64) bool {
	const epsilon = 1e-18 // threshold for difference
	return math.Abs(a-b) < epsilon
}
