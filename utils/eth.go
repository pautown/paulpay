package utils

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var ethAddresses = map[string][]Transfer{}
var ethTransactions = make(map[string][]TempETHTransaction)
var erc20Transactions = make(map[string][]TempERCTransaction)

type TempERCTransaction struct {
	BlockNumber       string `json:"blockNumber"`
	TimeStamp         string `json:"timeStamp"`
	Hash              string `json:"hash"`
	Nonce             string `json:"nonce"`
	BlockHash         string `json:"blockHash"`
	From              string `json:"from"`
	ContractAddress   string `json:"contractAddress"`
	To                string `json:"to"`
	Value             string `json:"value"`
	TokenName         string `json:"tokenName"`
	TokenSymbol       string `json:"tokenSymbol"`
	TokenDecimal      string `json:"tokenDecimal"`
	TransactionIndex  string `json:"transactionIndex"`
	Gas               string `json:"gas"`
	GasPrice          string `json:"gasPrice"`
	GasUsed           string `json:"gasUsed"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
	Input             string `json:"input"`
	Confirmations     string `json:"confirmations"`
}

type ERCResponse struct {
	Status  string               `json:"status"`
	Message string               `json:"message"`
	Result  []TempERCTransaction `json:"result"`
}

type TempETHTransaction struct {
	BlockNumber       string `json:"blockNumber"`
	TimeStamp         string `json:"timeStamp"`
	Hash              string `json:"hash"`
	Nonce             string `json:"nonce"`
	BlockHash         string `json:"blockHash"`
	TransactionIndex  string `json:"transactionIndex"`
	From              string `json:"from"`
	To                string `json:"to"`
	Value             string `json:"value"`
	Gas               string `json:"gas"`
	GasPrice          string `json:"gasPrice"`
	IsError           string `json:"isError"`
	Txreceipt_status  string `json:"txreceipt_status"`
	Input             string `json:"input"`
	ContractAddress   string `json:"contractAddress"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
	GasUsed           string `json:"gasUsed"`
	Confirmations     string `json:"confirmations"`
	MethodId          string `json:"methodId"`
	FunctionName      string `json:"functionName"`
}

type EthResponse struct {
	Status  string               `json:"status"`
	Message string               `json:"message"`
	Result  []TempETHTransaction `json:"result"`
}

func GetEth(eth_address string) ([]Transfer, bool, error) {

	/*check if eth_address is in ethAddresses*/
	if _, exists := ethAddresses[eth_address]; !exists {
		ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
		log.Println("eth address doesn't exist, checking.")
		return ethAddresses[eth_address], true, nil
	} else {
		newTX := false
		log.Println("eth address does exist, check if transactions are the same")
		if CheckNewETHTransactions(eth_address) {
			log.Println("NEW ETH TXS")
			ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
			newTX = true
		} else if CheckNewERCTransactions(eth_address) {
			log.Println("NEW ERC TXS")

			ethAddresses[eth_address], _ = GetEthTransactions(eth_address)
			newTX = true
		}
		log.Println("There are no new txs")
		return ethAddresses[eth_address], newTX, nil
	}

}

func CheckNewETHTransactions(eth_address string) bool {
	etherscanAPI, err := ioutil.ReadFile("./etherscan_api")
	if err != nil {
		log.Println("Error reading Etherscan API Key:", err)
		return false
	}

	url := "https://api.etherscan.io/api?module=account&action=txlist&address=" +
		eth_address + "&startblock=0&endblock=99999999&sort=asc&apikey=" + string(etherscanAPI)

	url = strings.ReplaceAll(url, "\n", "")

	resp, err := http.Get(url)
	if err != nil {
		log.Println("Error sending GET request:", err)
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return false
	}

	var response EthResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println("Error unmarshalling response body:", err)
		return false
	}

	if _, exists := ethTransactions[eth_address]; !exists {
		ethTransactions[eth_address] = response.Result
		log.Println("ethTransactions[eth_address] not found")
		return true
	} else {
		if len(ethTransactions[eth_address]) == len(response.Result) {
			log.Println("ethTransactions[eth_address] found but no new txs")
			return false
		} else {
			ethTransactions[eth_address] = response.Result
			log.Println("ethTransactions[eth_address] found and new txs")
			return true
		}
	}
}

func CheckNewERCTransactions(eth_address string) bool {
	etherscanAPI, err := ioutil.ReadFile("./etherscan_api")
	if err != nil {
		log.Println("Error reading Etherscan API Key:", err)
		return false
	}

	url := "https://api.etherscan.io/api?module=account&action=tokentx&address=" +
		eth_address + "&startblock=0&endblock=999999999&sort=asc&apikey=" + string(etherscanAPI)

	url = strings.ReplaceAll(url, "\n", "")

	resp, err := http.Get(url)
	if err != nil {
		log.Println("Error sending GET request:", err)
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return false
	}

	var response ERCResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Println("Error unmarshalling response body:", err)
		return false
	}

	if _, exists := erc20Transactions[eth_address]; !exists {
		erc20Transactions[eth_address] = response.Result
		log.Println("erc20Transactions[eth_address] not found")
		return true
	} else {
		if len(erc20Transactions[eth_address]) == len(response.Result) {
			log.Println("erc20Transactions[eth_address] found but no new txs")
			return false
		} else {
			log.Println("erc20Transactions[eth_address] found and new txs")
			erc20Transactions[eth_address] = response.Result
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
