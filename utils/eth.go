package utils

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

var ethAddresses = map[string][]Transfer
var ethTransactions = map[string]string
var erc20Transaction = map[string]string

func GetEth(eth_address string) ([]Transfer, error) {

	/*check if eth_address is in ethAddresses*/
	if _, exists := ethAddresses[eth_address]; !exists {
		ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
		log.Println("eth address doesn't exist, checking.")
		return ethAddresses[eth_address]
	} else {
		log.Println("eth address does exist, check if transactions are the same")
		if CheckNewEthTransactions(eth_address) {
			ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
		} else if CheckNewERCTransactions(eth_address) {
			ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
		}
		ethAddresses[eth_address]
	}
	/*
		if it isnt then call GetEthTransactions
		if it is  then check if its eth balance is the same
		https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey=YourApiKeyToken
		if its not then call GetEthTransactions
		if it is then check if the erc20 transactions are the same
		if it isn't then call GetEthTransactions
		if it is then return the old transactions*/

}

func CheckNewETHTransactions(eth_address) bool {
	// Read Etherscan API KEY from file
	etherscanAPI, err := ioutil.ReadFile("./etherscan_api")
	if err != nil {
		return nil, err
	}

	url := "https://api.etherscan.io/api?module=account&action=txlist&address=" +
		eth_address + "&startblock=0&endblock=99999999&sort=asc&apikey=" + string(etherscanAPI)

	url = strings.ReplaceAll(url, "\n", "")

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error sending GET request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	if _, exists := ethTransactions[eth_address]; !exists {
		ethTransactions[eth_address] = string(body)
		return false
	} else {
		if ethTransactions[eth_address] == string(body) {
			return false
		} else {
			return true
		}

	}
}

func CheckNewERCTransactions(eth_address) bool {
	// Read Etherscan API KEY from file
	etherscanAPI, err := ioutil.ReadFile("./etherscan_api")
	if err != nil {
		return nil, err
	}

	url := "https://api.etherscan.io/api?module=account&action=tokentx&address=" +
		eth_address + "&startblock=0&endblock=999999999&sort=asc&apikey=" + string(etherscanAPI)

	url = strings.ReplaceAll(url, "\n", "")

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error sending GET request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	if _, exists := ethTransactions[eth_address]; !exists {
		ethTransactions[eth_address] = string(body)
		return false
	} else {
		if ethTransactions[eth_address] == string(body) {
			return false
		} else {
			return true
		}

	}
}

func GetEthTransactions(eth_address string) ([]Transfer, error) {
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
	return transfers, nil
}
