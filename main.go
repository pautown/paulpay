package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gabstv/go-monero/walletrpc"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/portto/solana-go-sdk/client"
	"github.com/portto/solana-go-sdk/common"
	"github.com/portto/solana-go-sdk/program/system"
	"github.com/portto/solana-go-sdk/rpc"
	"github.com/portto/solana-go-sdk/types"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"html"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
	//"shadowchat/utils"
)

const username = "admin"

var USDMinimum float64 = 5
var MediaMin float64 = 0.025 // Currently unused
var MessageMaxChar int = 250
var NameMaxChar int = 25
var rpcURL string = "http://127.0.0.1:28088/json_rpc"
var solToUsd = 0.00
var ethToUsd = 0.00
var xmrToUsd = 0.00
var addressSliceSolana []AddressSolana

var checked string = ""
var killDono = 30.00 * time.Hour // hours it takes for a dono to be unfulfilled before it is no longer checked.
var indexTemplate *template.Template
var payTemplate *template.Template

var alertTemplate *template.Template
var progressbarTemplate *template.Template
var userOBSTemplate *template.Template
var viewTemplate *template.Template

var loginTemplate *template.Template
var incorrectLoginTemplate *template.Template
var userTemplate *template.Template
var logoutTemplate *template.Template
var incorrectPasswordTemplate *template.Template
var baseCheckingRate = 15

var minSolana, minMonero, minEthereum float64 // Global variables to hold minimum SOL and XMR and ETH required to equal the global value
var minDonoValue float64 = 5.0                // The global value to equal in USD terms
var lamportFee = 1000000

// Mainnet
var c = client.NewClient(rpc.MainnetRPCEndpoint)

// Devnet
var adminSolanaAddress = "9mP1PQXaXWQA44Fgt9PKtPKVvzXUFvrLD2WDLKcj9FVa"
var adminEthereumAddress = "adWqokePHcAbyF11TgfvvM1eKax3Kxtnn9sZVQh6fXo"
var adminHexcoinAddress = "9mP1PQXaXWQA44Fgt9PKtPKVvzXUFvrLD2WDLKcj9FVa"

//var c = client.NewClient(rpc.DevnetRPCEndpoint)

type priceData struct {
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
}

type UserPageData struct {
	ErrorMessage string
}

var ServerMinMediaDono = 5
var ServerMediaEnabled = true

var db *sql.DB
var userSessions = make(map[string]int)
var amountNeeded = 1000.00
var amountSent = 200.00

type getBalanceResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	Result  struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value uint64 `json:"value"`
	} `json:"result"`
	ID int `json:"id"`
}

type EthSuperChat struct {
	Name      string
	Message   string
	Media     string
	Amount    string
	CreatedAt string
	CheckedAt string
}

type superChat struct {
	Name     string
	Message  string
	Media    string
	Amount   string
	Address  string
	QRB64    string
	PayID    string
	CheckURL string
	IsSolana bool
}

type indexDisplay struct {
	MaxChar     int
	MinSolana   float64
	MinMonero   float64
	MinEthereum float64
	SolPrice    float64
	XMRPrice    float64
	ETHPrice    float64
	MinAmnt     float64
	Links       string
	Checked     string
}

type alertPageData struct {
	Name          string
	Message       string
	Amount        float64
	Currency      string
	MediaURL      string
	USDAmount     float64
	Refresh       int
	DisplayToggle string
}

type progressbarData struct {
	Message string
	Needed  float64
	Sent    float64
	Refresh int
}

type obsDataStruct struct {
	FilenameGIF string
	FilenameMP3 string
	URLdisplay  string
	URLdonobar  string
}

type rpcResponse struct {
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

var json_links []Link
var a alertPageData
var pb progressbarData
var obsData obsDataStruct
var pbMessage = "Stream Tomorrow"

// Define a new template that only contains the table content
var tableTemplate = template.Must(template.New("table").Parse(`
	{{range .}}
	<tr>
		<td>{{.UpdatedAt.Format "15:04:05 01-02-2006"}}</td>
		<td>{{.Name}}</td>
		<td>{{.Message}}</td>
		<td>${{.AmountToSend}}</td>
		<td>{{.AmountSent}}</td>
		<td>{{.CurrencyType}}</td>
	</tr>
	{{end}}
`))

func checkLoggedIn(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := getUserBySession(cookie.Value)
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user = user
	cookie = cookie
}

// Handler function for the "/donations" endpoint
func donationsHandler(w http.ResponseWriter, r *http.Request) {

	checkLoggedIn(w, r)
	// Fetch the latest data from your database or other data source

	// Retrieve data from the donos table
	rows, err := db.Query("SELECT * FROM donos WHERE fulfilled = 1 AND amount_sent != 0 ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the data
	var donos []Dono
	for rows.Next() {
		var dono Dono
		err := rows.Scan(&dono.ID, &dono.UserID, &dono.Address, &dono.Name, &dono.Message, &dono.AmountToSend, &dono.AmountSent, &dono.CurrencyType, &dono.AnonDono, &dono.Fulfilled, &dono.EncryptedIP, &dono.CreatedAt, &dono.UpdatedAt, &dono.USDAmount, &dono.MediaURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		donos = append(donos, dono)
	}
	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := donos

	// Execute the table template with the latest data
	err = tableTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {

	go startMoneroWallet()

	time.Sleep(5 * time.Second)

	log.Println("Starting server")

	var err error

	// Open a new database connection
	db, err = sql.Open("sqlite3", "users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Check if the database and tables exist, and create them if they don't
	err = createDatabaseIfNotExists(db)
	if err != nil {
		panic(err)
	}

	// Run migrations on database
	err = runDatabaseMigrations(db)
	if err != nil {
		panic(err)
	}

	// create a RPC client for Solana
	fmt.Println(reflect.TypeOf(c))

	// get the current running Solana version
	response, err := c.GetVersion(context.TODO())
	if err != nil {
		panic(err)
	}

	fmt.Println("version", response.SolanaCore)

	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/style.css")
	})
	http.HandleFunc("/xmr.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/xmr.svg")
	})

	http.HandleFunc("/eth.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/eth.svg")
	})

	http.HandleFunc("/dono.gif", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/obs/media/ezgif-1-fd55d7ca73.gif")
	})

	http.HandleFunc("/sol.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/sol.svg")
	})

	// Schedule a function to run fetchExchangeRates every three minutes
	go fetchExchangeRates()
	go checkDonos()

	a.Refresh = 10
	pb.Refresh = 1

	obsData.URLdonobar = "/progressbar"
	obsData.URLdisplay = "/alert"

	http.HandleFunc("/donations", donationsHandler)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/pay", paymentHandler)
	http.HandleFunc("/alert", alertOBSHandler)
	http.HandleFunc("/viewdonos", viewDonosHandler)

	http.HandleFunc("/progressbar", progressbarOBSHandler)

	// serve login and user interface pages
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/incorrect_login", incorrectLoginHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/userobs", userOBSHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/changepassword", changePasswordHandler)
	http.HandleFunc("/changeuser", changeUserHandler)
	getObsData(db, 1)

	indexTemplate, _ = template.ParseFiles("web/index.html")
	payTemplate, _ = template.ParseFiles("web/pay.html")
	alertTemplate, _ = template.ParseFiles("web/alert.html")

	userOBSTemplate, _ = template.ParseFiles("web/obs/settings.html")
	progressbarTemplate, _ = template.ParseFiles("web/obs/progressbar.html")

	loginTemplate, _ = template.ParseFiles("web/login.html")
	incorrectLoginTemplate, _ = template.ParseFiles("web/incorrect_login.html")
	userTemplate, _ = template.ParseFiles("web/user.html")
	logoutTemplate, _ = template.ParseFiles("web/logout.html")
	incorrectPasswordTemplate, _ = template.ParseFiles("web/password_change_failed.html")

	setServerVars()

	// go createTestDono("Huge Bob", "XMR", "Hey it's Huge Bob ", 0.1, 3, "https://www.youtube.com/watch?v=6iseNlvH2_s")
	// go createTestDono("Big Bob", "XMR", "Test message! Test message! Test message! Test message! Test message! Test message! Test message! Test message! Test message! ", 50, 100, "https://www.youtube.com/watch?v=6iseNlvH2_s")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob you foo", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob ", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob you foo", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob ", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob you foo", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob ", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob ", 0.1, 3, "")
	go createTestDono("Little Bob", "XMR", "Hey it's little Bob you foo", 0.1, 3, "")
	// go createTestDono("Medium Bob", "XMR", "Hey it's medium Bob ", 0.1, 3, "https://www.youtube.com/watch?v=6iseNlvH2_s")

	err = http.ListenAndServe(":8900", nil)
	if err != nil {
		panic(err)
	}

}

// get links for a user
func getUserLinks(user User) ([]Link, error) {
	if user.Links == "" {
		// Insert default links for the user
		defaultLinks := []Link{
			{URL: "https://powerchat.live/paultown?tab=donation", Description: "Powerchat"},
			{URL: "https://cozy.tv/paultown", Description: "cozy.tv/paultown"},
			{URL: "http://twitter.paul.town/", Description: "Twitter"},
			{URL: "https://t.me/paultownreal", Description: "Telegram"},
			{URL: "http://notes.paul.town/", Description: "notes.paul.town"},
		}

		jsonLinks, err := json.Marshal(defaultLinks)
		if err != nil {
			return nil, err
		}

		user.Links = string(jsonLinks)
		if err := updateUser(user); err != nil {
			return nil, err
		}

		return defaultLinks, nil
	}

	var links []Link
	if err := json.Unmarshal([]byte(user.Links), &links); err != nil {
		return nil, err
	}

	return links, nil
}

func setServerVars() {
	log.Println("Starting.")
	log.Println("		 ..")
	time.Sleep(2 * time.Second)
	log.Println("------------ setServerVars()")
	user, err := getUserByUsername(username)
	if err != nil {
		panic(err)
	}

	json_links, _ = getUserLinks(user)

	minDonoValue = float64(user.MinDono)
	adminSolanaAddress = user.SolAddress

	ServerMediaEnabled = user.MediaEnabled
	ServerMinMediaDono = user.MinMediaDono
	setMinDonos()
	log.Println("adminSolanaAddress:", adminSolanaAddress)
	log.Println("ServerMediaEnabled:", ServerMediaEnabled)
	log.Println("ServerMinMediaDono:", ServerMinMediaDono)

}
func createTestDono(name string, curr string, message string, amount float64, usdAmount float64, media_url string) {
	valid, media_url_ := checkDonoForMediaUSDThreshold(media_url, usdAmount)

	if valid == false {
		media_url_ = ""
	}

	log.Println("TESTING DONO IN FIVE SECONDS")
	time.Sleep(5 * time.Second)
	log.Println("TESTING DONO NOW")
	err := createNewQueueEntry(db, "TestAddress", name, message, amount, curr, usdAmount, media_url_)
	if err != nil {
		panic(err)
	}

	addDonoToDonoBar(amount, curr)
}

// extractVideoID extracts the video ID from a YouTube URL
func extractVideoID(url string) string {
	videoID := ""
	// Use a regular expression to extract the video ID from the YouTube URL
	re := regexp.MustCompile(`v=([\w-]+)`)
	match := re.FindStringSubmatch(url)
	if len(match) == 2 {
		videoID = match[1]
	}
	return videoID
}

func viewDonosHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := getUserBySession(cookie.Value)
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user = user
	cookie = cookie

	// Retrieve data from the donos table
	rows, err := db.Query("SELECT * FROM donos WHERE fulfilled = 1 AND amount_sent != 0 ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the data
	var donos []Dono
	for rows.Next() {
		var dono Dono
		var name, message, address, currencyType, encryptedIP, mediaURL sql.NullString
		var amountToSend, amountSent, usdAmount sql.NullFloat64
		var userID sql.NullInt64
		var anonDono, fulfilled sql.NullBool
		err := rows.Scan(&dono.ID, &userID, &address, &name, &message, &amountToSend, &amountSent, &currencyType, &anonDono, &fulfilled, &encryptedIP, &dono.CreatedAt, &dono.UpdatedAt, &usdAmount, &mediaURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		dono.UserID = int(userID.Int64)
		dono.Address = address.String
		dono.Name = name.String
		dono.Message = message.String
		dono.AmountToSend = amountToSend.Float64
		dono.AmountSent = amountSent.Float64
		dono.CurrencyType = currencyType.String
		dono.AnonDono = anonDono.Bool
		dono.Fulfilled = fulfilled.Bool
		dono.EncryptedIP = encryptedIP.String
		dono.USDAmount = usdAmount.Float64
		dono.MediaURL = mediaURL.String

		donos = append(donos, dono)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sort the data based on user input
	sortParam := r.FormValue("sort")
	switch sortParam {
	case "date":
		sort.Slice(donos, func(i, j int) bool {
			return donos[i].UpdatedAt.Before(donos[j].UpdatedAt)
		})
	case "amount":
		sort.Slice(donos, func(i, j int) bool {
			return donos[i].AmountToSend < donos[j].AmountToSend
		})
	}

	// Send the data to the template
	tpl, err := template.ParseFiles("web/view_donos.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.Execute(w, donos)
}

func setMinDonos() {

	// Calculate how much Monero is needed to equal the min usd donation var.
	minMonero = minDonoValue / xmrToUsd
	// Calculate how much Solana is needed to equal the min usd donation var.
	minSolana = minDonoValue / solToUsd
	// Calculate how much Solana is needed to equal the min usd donation var.
	minEthereum = minDonoValue / ethToUsd

	minMonero, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", minMonero), 64)
	minSolana, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", minSolana), 64)
	minEthereum, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", minEthereum), 64)

	log.Println("Minimum XMR Dono:", minMonero)
	log.Println("Minimum SOL Dono:", minSolana)
	log.Println("Minimum SOL Dono:", minEthereum)
}

func fetchExchangeRates() {
	for {
		// Fetch the exchange rate data from the API
		resp, err := http.Get("https://api.coingecko.com/api/v3/simple/price?ids=monero,solana,ethereum&vs_currencies=usd")
		if err != nil {
			fmt.Println("Error fetching price data:", err)
			// Wait five minutes before trying again
			time.Sleep(300 * time.Second)
			continue
		}
		defer resp.Body.Close()

		// Parse the JSON response
		var data priceData
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			fmt.Println("Error decoding price data:", err)
			// Wait five minutes before trying again
			time.Sleep(300 * time.Second)
			continue
		}

		// Update the exchange rate values
		xmrToUsd = data.Monero.Usd
		solToUsd = data.Solana.Usd
		solToUsd = data.Ethereum.Usd

		fmt.Println("Updated exchange rates:", " 1 XMR:", "$"+fmt.Sprintf("%.2f", xmrToUsd), "1 SOL:", "$"+fmt.Sprintf("%.2f", solToUsd), "1 ETH:", "$"+fmt.Sprintf("%.2f", ethToUsd))

		// Calculate how much Monero is needed to equal the min usd donation var.
		minMonero = minDonoValue / data.Monero.Usd
		// Calculate how much Solana is needed to equal the min usd donation var.
		minSolana = minDonoValue / data.Solana.Usd
		// Calculate how much Ethereum is needed to equal the min usd donation var.
		minEthereum = minDonoValue / data.Ethereum.Usd

		minMonero, _ = strconv.ParseFloat(fmt.Sprintf("%.4f", minMonero), 64)
		minSolana, _ = strconv.ParseFloat(fmt.Sprintf("%.4f", minSolana), 64)
		minEthereum, _ = strconv.ParseFloat(fmt.Sprintf("%.4f", minEthereum), 64)

		// Save the minimum Monero and Solana variables
		fmt.Println("Minimum Dono:", "$"+fmt.Sprintf("%.2f", minDonoValue), "- XMR:", minMonero, "SOL:", minSolana, "ETH:", minEthereum)

		// Wait three minutes before fetching again
		if xmrToUsd == 0 || solToUsd == 0 || ethToUsd == 0 {
			time.Sleep(180 * time.Second)
		} else {
			time.Sleep(30 * time.Second)
		}

	}
}

func startMoneroWallet() {
	//linux
	cmd := exec.Command("monero/monero-wallet-rpc", "--rpc-bind-port", "28088", "--daemon-address", "https://xmr-node.cakewallet.com:18081", "--wallet-file", "monero/wallet", "--disable-rpc-login", "--password", "")

	//windows
	//cmd := exec.Command("monero/monero-wallet-rpc.exe", "--rpc-bind-port", "28088", "--daemon-address", "https://xmr-node.cakewallet.com:18081", "--wallet-file", "monero/wallet", "--disable-rpc-login", "--password", "")
	// Capture the output of the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running command: %v\n", err)
		return
	}

	// Start a wallet client instance
	clientXMR := walletrpc.New(walletrpc.Config{
		Address: "http://127.0.0.1:28088/json_rpc",
	})

	// check wallet balance
	balance, unlocked, err := clientXMR.GetBalance()

	log.Println(walletrpc.XMRToDecimal(balance), unlocked, err)

	// Print the output of the command
	fmt.Println(string(output))
}

func stopMoneroWallet() {
	cmd := exec.Command("monero/monero-wallet-rpc.exe", "--rpc-bind-port", "28088", "--command", "stop_wallet")

	// Capture the output of the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running command: %v\n", err)
		return
	}

	// Print the output of the command
	fmt.Println(string(output))
}

func checkDonos() {
	for {
		fulfilledDonos := checkUnfulfilledDonos()
		if len(fulfilledDonos) > 0 {
			fmt.Println("Fulfilled Donos:")
		}

		for _, dono := range fulfilledDonos {
			fmt.Println(dono)

			err := createNewQueueEntry(db, dono.Address, dono.Name, dono.Message, dono.AmountSent, dono.CurrencyType, dono.USDAmount, dono.MediaURL)
			if err != nil {
				panic(err)
			}

		}
		time.Sleep(time.Duration(baseCheckingRate) * time.Second)
	}
}

func getUSDValue(as float64, c string) float64 {
	usdVal := 0.00

	if c == "XMR" {
		usdVal = as * xmrToUsd
	} else if c == "SOL" {
		usdVal = as * solToUsd
	}

	usdValStr := fmt.Sprintf("%.2f", usdVal)      // format usdVal as a string with 2 decimal points
	usdVal, _ = strconv.ParseFloat(usdValStr, 64) // convert the string back to a float

	return usdVal
}

func addDonoToDonoBar(as float64, c string) float64 {
	usdVal := getUSDValue(as, c)
	pb.Sent += usdVal

	sent, err := strconv.ParseFloat(fmt.Sprintf("%.2f", pb.Sent), 64)
	if err != nil {
		// handle the error here
		log.Println("Error converting to cents: ", err)
	}
	pb.Sent = sent

	amountSent = pb.Sent

	err = updateObsData(db, 1, 1, obsData.FilenameGIF, obsData.FilenameMP3, "alice", pb)

	if err != nil {
		log.Println("Error: ", err)
		return 0.00
	}
	return usdVal
}

func formatMediaURL(media_url string) string {
	isValid, timecode, properLink := isYouTubeLink(media_url)
	log.Println(isValid, timecode, properLink)

	embedLink := ""
	// extract the video ID from the YouTube URL
	if isValid {
		videoID := extractVideoID(properLink)
		// Build the embeddable video link
		embedLink = fmt.Sprintf(videoID)
	}
	return embedLink
}

func createNewQueueEntry(db *sql.DB, address string, name string, message string, amount float64, currency string, dono_usd float64, media_url string) error {

	// extract the video ID (if any) from the YouTube URL
	embedLink := formatMediaURL(media_url)

	_, err := db.Exec(`
		INSERT INTO queue (name, message, amount, currency, usd_amount, media_url) VALUES (?, ?, ?, ?, ?, ?)
	`, name, message, amount, currency, dono_usd, embedLink)
	if err != nil {
		return err
	}
	return nil
}

func isYouTubeLink(link string) (bool, int, string) {
	var timecode int
	var properLink string

	youtubeRegex := regexp.MustCompile(`^(?:https?://)?(?:www\.)?(?:youtube\.com/watch\?v=|youtu\.be/)([^&]+)(?:\?t=)?(\d*)$`)
	embedRegex := regexp.MustCompile(`^(?:https?://)?(?:www\.)?youtube\.com/embed/([^?]+)(?:\?start=)?(\d*)$`)

	if youtubeMatches := youtubeRegex.FindStringSubmatch(link); youtubeMatches != nil {
		if len(youtubeMatches[2]) > 0 {
			fmt.Sscanf(youtubeMatches[2], "%d", &timecode)
		}
		properLink = "https://www.youtube.com/watch?v=" + youtubeMatches[1]
		return true, timecode, properLink
	}

	if embedMatches := embedRegex.FindStringSubmatch(link); embedMatches != nil {
		if len(embedMatches[2]) > 0 {
			fmt.Sscanf(embedMatches[2], "%d", &timecode)
		}
		properLink = "https://www.youtube.com/watch?v=" + embedMatches[1]
		return true, timecode, properLink
	}

	return false, 0, ""
}

func checkDonoForMediaUSDThreshold(media_url string, dono_usd float64) (bool, string) {
	valid := true
	if dono_usd < float64(ServerMinMediaDono) {
		media_url = ""
		valid = false

	}
	return valid, media_url
}

func createNewDono(user_id int, dono_address string, dono_name string, dono_message string, amount_to_send float64, currencyType string, encrypted_ip string, anon_dono bool, dono_usd float64, media_url string) {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {

		panic(err)
	}
	defer db.Close()

	// Get current time
	createdAt := time.Now().UTC()

	valid, media_url_ := checkDonoForMediaUSDThreshold(media_url, dono_usd)

	if valid == false {
		media_url_ = ""
	}

	// Execute the SQL INSERT statement
	_, err = db.Exec(`
		INSERT INTO donos (
			user_id,
			dono_address,
			dono_name,
			dono_message,
			amount_to_send,
			amount_sent,
			currency_type,
			anon_dono,
			fulfilled,
			encrypted_ip,
			created_at,
			updated_at,
			usd_amount,
			media_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, user_id, dono_address, dono_name, dono_message, amount_to_send, 0.0, currencyType, anon_dono, false, encrypted_ip, createdAt, createdAt, dono_usd, media_url_)
	if err != nil {
		log.Println(err)
		panic(err)
	}
}

type Dono struct {
	ID           int
	UserID       int
	Address      string
	Name         string
	Message      string
	AmountToSend float64
	AmountSent   float64
	CurrencyType string
	AnonDono     bool
	Fulfilled    bool
	EncryptedIP  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	USDAmount    float64
	MediaURL     string
}

func clearEncryptedIP(dono *Dono) {
	dono.EncryptedIP = ""
}

func encryptIP(ip string) string {
	h := sha256.New()
	h.Write([]byte("IPFingerprint" + ip))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash)
}

func getUnfulfilledDonoIPs() ([]string, error) {
	ips := []string{}

	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT ip FROM donos WHERE fulfilled = false`)
	if err != nil {
		return ips, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		err := rows.Scan(&ip)
		if err != nil {
			return ips, err
		}
		ips = append(ips, ip)
	}

	err = rows.Err()
	if err != nil {
		return ips, err
	}

	return ips, nil
}

func checkUnfulfilledDonos() []Dono {
	ips, _ := getUnfulfilledDonoIPs() // get ips

	// Open a new database connection
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Retrieve all unfulfilled donos from the database
	rows, err := db.Query(`SELECT * FROM donos WHERE fulfilled = false`)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var fulfilledSlice []bool
	var amountSlice []float64
	var amountUSDSlice []float64
	var fulfilledDonos []Dono
	var rowsToUpdate []int // slice to store row ids to be updated
	var dono Dono
	var tmpUSDAmount, tmpAmountToSend, tmpAmountSent sql.NullFloat64
	var tmpMediaURL sql.NullString

	for rows.Next() { // Loop through the unfulfilled donos and check their status
		err := rows.Scan(&dono.ID, &dono.UserID, &dono.Address, &dono.Name, &dono.Message, &tmpAmountToSend, &tmpAmountSent, &dono.CurrencyType, &dono.AnonDono, &dono.Fulfilled, &dono.EncryptedIP, &dono.CreatedAt, &dono.UpdatedAt, &tmpUSDAmount, &tmpMediaURL)

		if err != nil {
			panic(err)
		}

		if tmpUSDAmount.Valid {
			dono.USDAmount = tmpUSDAmount.Float64
		} else {
			// Handle NULL value
			dono.USDAmount = 0.0 // or any default value you want to assign
		}

		if tmpAmountToSend.Valid {
			dono.AmountToSend = tmpAmountToSend.Float64
		} else {
			// Handle NULL value
			dono.AmountToSend = 0.0 // or any default value you want to assign
		}

		if tmpAmountSent.Valid {
			dono.AmountSent = tmpAmountSent.Float64
		} else {
			// Handle NULL value
			dono.AmountSent = 0.0 // or any default value you want to assign
		}

		if tmpMediaURL.Valid {
			dono.MediaURL = tmpMediaURL.String
		} else {
			// Handle NULL value
			dono.MediaURL = "" // or any default value you want to assign
		}

		// Check if the dono has exceeded the killDono time
		timeElapsedFromDonoCreation := time.Since(dono.CreatedAt)
		if timeElapsedFromDonoCreation > killDono || dono.Address == " " || dono.AmountToSend == 0.00 {
			dono.Fulfilled = true
			rowsToUpdate = append(rowsToUpdate, dono.ID)
			// add true to fulfilledSlice
			fulfilledSlice = append(fulfilledSlice, true)

			amountSlice = append(amountSlice, dono.AmountSent)
			amountUSDSlice = append(amountUSDSlice, dono.AmountToSend)
			if dono.Address == " " {
				log.Println("No dono address, killed (marked as fulfilled) and won't be checked again. \n")
			} else {
				log.Println("Dono too old, killed (marked as fulfilled) and won't be checked again. \n")
			}
			continue
		}

		// Check if the dono needs to be skipped based on exponential backoff
		secondsElapsedSinceLastCheck := time.Since(dono.UpdatedAt).Seconds()

		expoAdder := returnIPPenalty(ips, dono.EncryptedIP) + time.Since(dono.CreatedAt).Seconds()/60/60/19
		secondsNeededToCheck := math.Pow(float64(baseCheckingRate)-0.02, expoAdder)
		log.Println("Dono ID:", dono.ID, "Name:", dono.Name)
		log.Println("Message:", dono.Message)
		log.Println(dono.CurrencyType, "Needed:", dono.AmountToSend, "Recieved:", dono.AmountSent)
		log.Println("Address:", dono.Address)
		log.Println("Time since check:", fmt.Sprintf("%.2f", secondsElapsedSinceLastCheck), "Needed:", fmt.Sprintf("%.2f", secondsNeededToCheck))

		if secondsElapsedSinceLastCheck < secondsNeededToCheck {
			log.Println("Not enough time has passed, skipping. \n")
			continue // If not enough time has passed then ignore
		}
		log.Println("Enough time has passed, checking.")

		if dono.CurrencyType == "XMR" {
			dono.AmountSent, _ = getXMRBalance(dono.Address)
		} else if dono.CurrencyType == "SOL" {
			dono.AmountSent, _ = getSOLBalance(dono.Address)
		}

		log.Println("New Amount Recieved:", dono.AmountSent, "\n")

		if dono.AmountSent >= dono.AmountToSend-float64(lamportFee)/1e9 && dono.AmountToSend != 0 {
			if dono.CurrencyType == "SOL" {
				wallet, _ := ReadAddress(dono.Address)
				SendSolana(wallet.KeyPublic, wallet.KeyPrivate, adminSolanaAddress, dono.AmountSent, dono.CurrencyType)
			}
			dono.AmountToSend = addDonoToDonoBar(dono.AmountSent, dono.CurrencyType) // change Amount To Send to USD value of sent

			dono.Fulfilled = true
			// add true to fulfilledSlice
			fulfilledDonos = append(fulfilledDonos, dono)
			rowsToUpdate = append(rowsToUpdate, dono.ID)
			fulfilledSlice = append(fulfilledSlice, true)
			amountSlice = append(amountSlice, dono.AmountSent)
			amountUSDSlice = append(amountUSDSlice, dono.AmountToSend)
			log.Println("Dono FULFILLED and sent to home sol address and won't be checked again. \n")
			continue
		}

		// add to slices
		fulfilledSlice = append(fulfilledSlice, false)
		rowsToUpdate = append(rowsToUpdate, dono.ID)
		amountSlice = append(amountSlice, dono.AmountSent)
		amountUSDSlice = append(amountUSDSlice, dono.AmountToSend)

	}

	i := 0
	// Update rows to be update in a way that never throws a database locked error
	for _, rowID := range rowsToUpdate {
		_, err = db.Exec(`UPDATE donos SET updated_at = ?, fulfilled = ?, amount_sent = ?, amount_to_send = ? WHERE dono_id = ?`, time.Now(), fulfilledSlice[i], amountSlice[i], amountUSDSlice[i], rowID)
		if err != nil {
			panic(err)
		}
		i += 1
	}

	return fulfilledDonos
}

func getSOLBalance(address string) (float64, error) {
	balance, err := c.GetBalance(
		context.TODO(), // request context
		address,        // wallet to fetch balance for
	)
	if err != nil {
		return 0, err
	}
	return float64(balance) / 1e9, nil
}
func getXMRBalance(checkID string) (float64, error) {
	url := "http://localhost:28088/json_rpc"

	payload := struct {
		Jsonrpc string `json:"jsonrpc"`
		Id      int    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			PaymentID string `json:"payment_id"`
		} `json:"params"`
	}{
		Jsonrpc: "2.0",
		Id:      0,
		Method:  "get_payments",
		Params: struct {
			PaymentID string `json:"payment_id"`
		}{
			PaymentID: checkID,
		},
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0, err
	}

	fmt.Println(result)

	resultMap, ok := result["result"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("result key not found in response")
	}

	payments, ok := resultMap["payments"].([]interface{})
	if !ok {
		return 0, fmt.Errorf("payments key not found in result map")
	}

	if len(payments) == 0 {
		return 0, fmt.Errorf("no payments found for payment ID %s", checkID)
	}

	amount := payments[0].(map[string]interface{})["amount"].(float64)

	return (amount / math.Pow(10, 12)), nil
}

func processQueue(db *sql.DB) error {

	// Retrieve oldest entry from queue table
	row := db.QueryRow(`
		SELECT id, name, amount, currency FROM queue
		ORDER BY created_at ASC LIMIT 1
	`)

	var id int
	var name string
	var amount float64
	var currency string
	err := row.Scan(&id, &name, &amount, &currency)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	// Check if we can display a new dono
	if displayNewDono(name, amount, currency) {
		_, err = db.Exec(`
			DELETE FROM queue WHERE id = ?
		`, id)
		if err != nil {
			return err
		}
	}

	return nil
}

// CreateAddress inserts a new address into the database.
func CreateAddress(addr AddressSolana) error {
	// Convert the private key to a byte slice.
	privateKeyBytes := []byte(addr.KeyPrivate)

	// Insert the address into the database.
	_, err := db.Exec("INSERT INTO addresses (key_public, key_private) VALUES (?, ?)",
		addr.KeyPublic, privateKeyBytes)
	return err
}

// ReadAddress reads an address from the database by public key.
func ReadAddress(publicKey string) (*AddressSolana, error) {
	// Query the database for the address.
	row := db.QueryRow("SELECT key_public, key_private FROM addresses WHERE key_public = ?", publicKey)

	var keyPublic string
	var privateKeyBytes []byte
	err := row.Scan(&keyPublic, &privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Convert the private key byte slice to an ed25519.PrivateKey.
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// Create a new AddressSolana object.
	addr := AddressSolana{
		KeyPublic:  keyPublic,
		KeyPrivate: privateKey,
	}

	return &addr, nil
}

// UpdateAddress updates an existing address in the database.
func UpdateAddress(addr AddressSolana) error {
	// Convert the private key to a byte slice.
	privateKeyBytes := []byte(addr.KeyPrivate)

	// Update the address in the database.
	_, err := db.Exec("UPDATE addresses SET key_private = ? WHERE key_public = ?",
		privateKeyBytes, addr.KeyPublic)
	return err
}

// DeleteAddress deletes an address from the database by public key.
func DeleteAddress(publicKey string) error {
	_, err := db.Exec("DELETE FROM addresses WHERE key_public = ?", publicKey)
	return err
}

func displayNewDono(name string, amount float64, currency string) bool {
	return false
}

func runDatabaseMigrations(db *sql.DB) error {
	tables := []string{"queue", "donos"}

	for _, table := range tables {
		err := addColumnIfNotExist(db, table, "usd_amount", "FLOAT")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, table, "media_url", "TEXT")
		if err != nil {
			return err
		}
	}

	tables = []string{"users"}

	for _, table := range tables {
		err := addColumnIfNotExist(db, table, "links", "TEXT")
		if err != nil {
			return err
		}
	}

	return nil
}

func addColumnIfNotExist(db *sql.DB, tableName, columnName, columnType string) error {
	if !checkDatabaseColumnExist(db, tableName, columnName) {
		_, err := db.Exec(`ALTER TABLE ` + tableName + ` ADD COLUMN ` + columnName + ` ` + columnType)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkDatabaseColumnExist(db *sql.DB, dbTable string, dbColumn string) bool {
	// check if column already exists
	var count int
	err := db.QueryRow("SELECT count(*) FROM pragma_table_info('" + dbTable + "') WHERE name='" + dbColumn + "'").Scan(&count)
	if err != nil {
		return false
	}

	// column doesn't exist
	if count == 0 {
		return false
	}
	return true // column does exist
}

func createDatabaseIfNotExists(db *sql.DB) error {
	// create the tables if they don't exist
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS donos (
            dono_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            dono_address TEXT,
            dono_name TEXT,
            dono_message TEXT,
            amount_to_send FLOAT,            
            amount_sent FLOAT,
            currency_type TEXT,
            anon_dono BOOL,
            fulfilled BOOL,
            encrypted_ip TEXT,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS addresses (
            key_public TEXT NOT NULL,
            key_private BLOB NOT NULL
        )
    `)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS queue (
            name TEXT,
            message TEXT,
            amount FLOAT,
            currency TEXT
        )
    `)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            HashedPassword BLOB,
            eth_address TEXT,
            sol_address TEXT,
            hex_address TEXT,
            xmr_wallet_password TEXT,
            min_donation_threshold FLOAT,
            min_media_threshold FLOAT,
            media_enabled BOOL,
            created_at DATETIME,
            modified_at DATETIME
        )
    `)

	if err != nil {
		return err
	}

	err = createObsTable(db)
	if err != nil {
		log.Fatal(err)
	}

	emptyTable, err := checkObsData(db)
	if err != nil {
		log.Fatal(err)
	}

	if emptyTable {
		pbData := progressbarData{
			Message: "test message",
			Needed:  100.0,
			Sent:    50.0,
			Refresh: 5,
		}
		err = insertObsData(db, 1, "test.gif", "test.mp3", "test_voice", pbData)
		if err != nil {
			log.Fatal(err)
		}
	}

	// create admin user if not exists
	adminUser := User{
		Username:          "admin",
		EthAddress:        "asl12312qse123we1232323lol",
		SolAddress:        "solololololololololsbfjeew",
		HexcoinAddress:    "realmoneyrealmoney123BMIhi",
		XMRWalletPassword: "",
		MinDono:           3,
		MinMediaDono:      5,
		MediaEnabled:      true,
	}

	adminHashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	adminUser.HashedPassword = adminHashedPassword

	err = createUser(adminUser)
	if err != nil {
		log.Println(err)
	}

	return nil
}

func createObsTable(db *sql.DB) error {
	obsTable := `
        CREATE TABLE IF NOT EXISTS obs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            gif_name TEXT,
            mp3_name TEXT,
            tts_voice TEXT,
            message TEXT,
            needed FLOAT,
            sent FLOAT
        );`
	_, err := db.Exec(obsTable)
	return err
}

func insertObsData(db *sql.DB, userId int, gifName, mp3Name, ttsVoice string, pbData progressbarData) error {
	obsData := `
        INSERT INTO obs (
            user_id,
            gif_name,
            mp3_name,
            tts_voice,
            message,
            needed,
            sent
        ) VALUES (?, ?, ?, ?, ?, ?, ?);`
	_, err := db.Exec(obsData, userId, gifName, mp3Name, ttsVoice, pbData.Message, pbData.Needed, pbData.Sent)
	return err
}

func checkObsData(db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM obs").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func updateObsData(db *sql.DB, obsId int, userId int, gifName string, mp3Name string, ttsVoice string, pbData progressbarData) error {

	updateObsData := `
        UPDATE obs
        SET user_id = ?,
            gif_name = ?,
            mp3_name = ?,
            tts_voice = ?,
            message = ?,
            needed = ?,
            sent = ?
        WHERE id = ?;`
	_, err := db.Exec(updateObsData, userId, gifName, mp3Name, ttsVoice, pbData.Message, pbData.Needed, pbData.Sent, obsId)
	return err
}

func getObsData(db *sql.DB, userId int) {
	err := db.QueryRow("SELECT gif_name, mp3_name, `message`, needed, sent FROM obs WHERE user_id = ?", userId).
		Scan(&obsData.FilenameGIF, &obsData.FilenameMP3, &pbMessage, &amountNeeded, &amountSent)
	if err != nil {
		log.Println("Error:", err)
	}

	log.Println(pbMessage)
	log.Println(amountNeeded)
	log.Println(amountSent)
}

func createUser(user User) error {

	// Insert the user's data into the database
	_, err := db.Exec(`
        INSERT INTO users (
            username,
            HashedPassword,
            eth_address,
            sol_address,
            hex_address,
            xmr_wallet_password,
            min_donation_threshold,
            min_media_threshold,
            media_enabled,
            created_at,
            modified_at,
            links
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, user.Username, user.HashedPassword, user.EthAddress, user.SolAddress, user.HexcoinAddress, "", user.MinDono, user.MinMediaDono, user.MediaEnabled, time.Now(), time.Now(), "")

	adminEthereumAddress = user.EthAddress
	adminSolanaAddress = user.SolAddress
	adminHexcoinAddress = user.HexcoinAddress
	minDonoValue = float64(user.MinDono)

	return err
}

// update an existing user
func updateUser(user User) error {
	statement := `
		UPDATE users
		SET Username=?, HashedPassword=?, eth_address=?, sol_address=?, hex_address=?,
			xmr_wallet_password=?, min_donation_threshold=?, min_media_threshold=?, media_enabled=?, modified_at=datetime('now'), links=?
		WHERE id=?
	`
	_, err := db.Exec(statement, user.Username, user.HashedPassword, user.EthAddress,
		user.SolAddress, user.HexcoinAddress, user.XMRWalletPassword, user.MinDono, user.MinMediaDono,
		user.MediaEnabled, []byte(user.Links), user.UserID) // convert user.Links to []byte
	if err != nil {
		log.Fatalf("failed, err: %v", err)
	}
	return err
}

// get a user by their username
func getUserByUsername(username string) (User, error) {
	var user User
	var links sql.NullString // use a sql.NullString for the "links" field
	row := db.QueryRow("SELECT * FROM users WHERE Username=?", username)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links) // scan into the sql.NullString
	if err != nil {
		return User{}, err
	}
	user.Links = links.String // assign the sql.NullString to the user's "Links" field
	if !links.Valid {         // check if the "links" column is null
		user.Links = "" // set the user's "Links" field to ""
	}
	return user, nil
}

// get a user by their session token
func getUserBySession(sessionToken string) (User, error) {
	userID, ok := userSessions[sessionToken]
	if !ok {
		return User{}, fmt.Errorf("session token not found")
	}
	var user User
	row := db.QueryRow("SELECT * FROM users WHERE id=?", userID)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &user.Links)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// verify that the entered password matches the stored hashed password for a user
func verifyPassword(user User, password string) bool {
	err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := getUserByUsername(username)

		if err != nil {
			if err.Error() == "sql: no rows in result set" { // can't find username in DB
				http.Redirect(w, r, "/incorrect_login", http.StatusFound)
				return
			}

			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if user.UserID == 0 || !verifyPassword(user, password) {
			http.Redirect(w, r, "/incorrect_login", http.StatusFound)
			return
		}

		sessionToken, err := createSession(user.UserID)
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
		})
		http.Redirect(w, r, "/user", http.StatusFound)
		return
	}
	tmpl := template.Must(template.ParseFiles("web/login.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func userOBSHandler(w http.ResponseWriter, r *http.Request) {
	checkLoggedIn(w, r)

	host := r.Host // get host url
	obsData.URLdonobar = host + "/progressbar"
	obsData.URLdisplay = host + "/alert"

	if r.Method == http.MethodPost {
		r.ParseMultipartForm(10 << 20) // max file size of 10 MB

		// Get the files from the request
		fileGIF, handlerGIF, err := r.FormFile("dono_animation")
		if err == nil {
			defer fileGIF.Close()

			// Save the file to the server
			fileNameGIF := handlerGIF.Filename
			fileBytesGIF, err := ioutil.ReadAll(fileGIF)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err = os.WriteFile("web/obs/media/"+fileNameGIF, fileBytesGIF, 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			obsData.FilenameGIF = fileNameGIF
		}

		fileMP3, handlerMP3, err := r.FormFile("dono_sound")
		if err == nil {
			defer fileMP3.Close()

			fileNameMP3 := handlerMP3.Filename
			fileBytesMP3, err := ioutil.ReadAll(fileMP3)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err = os.WriteFile("web/obs/media/"+fileNameMP3, fileBytesMP3, 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			obsData.FilenameMP3 = fileNameMP3
		}

		pbMessage = r.FormValue("message")
		amountNeededStr := r.FormValue("needed")
		amountSentStr := r.FormValue("sent")

		amountNeeded, err = strconv.ParseFloat(amountNeededStr, 64)
		if err != nil {
			// handle the error
			log.Println(err)
		}

		amountSent, err = strconv.ParseFloat(amountSentStr, 64)
		if err != nil {
			// handle the error
			log.Println(err)
		}
		pb.Message = pbMessage
		pb.Needed = amountNeeded
		pb.Sent = amountSent

		err = updateObsData(db, 1, 1, obsData.FilenameGIF, obsData.FilenameMP3, "alice", pb)

		if err != nil {
			log.Println("Error: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {

		getObsData(db, 1)
	}

	tmpl, err := template.ParseFiles("web/obs/settings.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type combinedData struct {
		obsDataStruct
		progressbarData
	}

	tnd := combinedData{obsData, pb}

	tmpl.Execute(w, tnd)

}

// handle requests to modify user data
func userHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := getUserBySession(cookie.Value)
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		user.Username = r.FormValue("username")
		user.EthAddress = r.FormValue("ethaddress")
		user.SolAddress = r.FormValue("soladdress")
		user.HexcoinAddress = r.FormValue("hexcoinaddress")
		user.XMRWalletPassword = r.FormValue("xmrwalletpassword")
		minDono, _ := strconv.Atoi(r.FormValue("mindono"))
		user.MinDono = minDono
		minMediaDono, _ := strconv.Atoi(r.FormValue("minmediadono"))
		user.MinMediaDono = minMediaDono
		mediaEnabled := r.FormValue("mediaenabled") == "on"
		user.MediaEnabled = mediaEnabled

		err := updateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setMinDonos()
	tmpl.Execute(w, user)

}

func generateSessionToken(user User) string {
	// generate a random session token
	b := make([]byte, 32)
	rand.Read(b)
	sessionToken := base64.URLEncoding.EncodeToString(b)
	// save the session token in a map
	userSessions[sessionToken] = user.UserID
	return sessionToken
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// retrieve user from session
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user, err := getUserBySession(sessionToken.Value)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// initialize user page data struct
	data := UserPageData{}

	// process form submission
	if r.Method == "POST" {
		// check current password
		if !verifyPassword(user, r.FormValue("current_password")) {
			// set user page data values
			data.ErrorMessage = "Current password entered was incorrect"
			// render password change failed form
			tmpl, err := template.ParseFiles("web/password_change_failed.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, data)
			return
		} else {
			// hash new password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("new_password")), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// update user password in database
			user.HashedPassword = hashedPassword
			err = updateUser(user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// redirect to user page
			http.Redirect(w, r, "/user", http.StatusSeeOther)
			return
		}
	}

	// render change password form
	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func changeUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting change user handler function")
	// retrieve user from session
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user, err := getUserBySession(sessionToken.Value)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// initialize user page data struct
	data := UserPageData{}

	// process form submission
	if r.Method == "POST" {
		user.EthAddress = r.FormValue("ethereumAddress")
		adminEthereumAddress = user.EthAddress
		user.SolAddress = r.FormValue("solanaAddress")
		adminSolanaAddress = user.SolAddress
		user.HexcoinAddress = r.FormValue("hexcoinAddress")
		adminHexcoinAddress = user.HexcoinAddress
		minDono, _ := strconv.Atoi(r.FormValue("minUsdAmount"))
		user.MinDono = minDono
		minDonoValue = float64(minDono)
		log.Println("Begin write to user")
		err = updateUser(user)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("wrote to user")
		// redirect to user page
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		log.Println("redirect to user")
		return
	}

	// render change password form
	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func renderChangePasswordForm(w http.ResponseWriter, data UserPageData) {
	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// invalidate session token and redirect user to home page
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func incorrectLoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("web/incorrect_login.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func createSession(userID int) (string, error) {
	sessionToken := uuid.New().String()
	userSessions[sessionToken] = userID
	return sessionToken, nil
}

func validateSession(r *http.Request) (int, error) {
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		return 0, fmt.Errorf("no session token found")
	}
	userID, ok := userSessions[sessionToken.Value]
	if !ok {
		return 0, fmt.Errorf("invalid session token")
	}
	return userID, nil
}

func createWalletSolana(dName string, dString string, dAmount float64, dAnon bool) AddressSolana {
	wallet := types.NewAccount()

	address := AddressSolana{}
	address.KeyPublic = wallet.PublicKey.ToBase58()
	address.KeyPrivate = wallet.PrivateKey
	address.DonoName = dName
	address.DonoAmount = dAmount
	address.DonoString = dString
	address.DonoAnon = dAnon
	addToAddressSliceSolana(address)
	CreateAddress(address)

	return address
}

func addToAddressSliceSolana(a AddressSolana) {
	addressSliceSolana = append(addressSliceSolana, a)
	fmt.Println(len(addressSliceSolana))
}

func condenseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func truncateStrings(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n]
}

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func alertOBSHandler(w http.ResponseWriter, r *http.Request) {
	newDono, err := checkDonoQueue(db)
	if err != nil {
		log.Printf("Error checking donation queue: %v\n", err)
	}

	if newDono {
		fmt.Println("Showing NEW DONO!")
	} else {
		a.MediaURL = ""
		a.DisplayToggle = "display: none;"
		a.Refresh = 3
	}
	err = alertTemplate.Execute(w, a)
	if err != nil {
		fmt.Println(err)
	}
}

func progressbarOBSHandler(w http.ResponseWriter, r *http.Request) {

	pb.Message = pbMessage
	pb.Needed = amountNeeded
	pb.Sent = amountSent

	err := progressbarTemplate.Execute(w, pb)
	if err != nil {
		fmt.Println(err)
	}

}

func getCurrentDateTime() string {
	now := time.Now()
	return now.Format("2006-01-02 15:04:05")
}

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	linksJSON, err := json.Marshal(json_links)
	if err != nil {
		fmt.Println(err)
		return
	}

	var links []Link
	err = json.Unmarshal(linksJSON, &links)
	if err != nil {
		fmt.Println(err)
		return
	}

	i := indexDisplay{
		MaxChar:     MessageMaxChar,
		MinSolana:   minSolana,
		MinEthereum: minEthereum,
		MinMonero:   minMonero,
		SolPrice:    solToUsd,
		XMRPrice:    xmrToUsd,
		Checked:     checked,
		Links:       string(linksJSON),
	}

	err = indexTemplate.Execute(w, i)
	if err != nil {
		fmt.Println(err)
	}
}

func checkDonoQueue(db *sql.DB) (bool, error) {

	// Fetch oldest entry from queue table
	row := db.QueryRow("SELECT name, message, amount, currency, media_url, usd_amount FROM queue ORDER BY rowid LIMIT 1")

	var name string
	var message string
	var amount float64
	var currency string
	var media_url string
	var usd_amount float64

	err := row.Scan(&name, &message, &amount, &currency, &media_url, &usd_amount)
	if err == sql.ErrNoRows {
		// Queue is empty, do nothing
		return false, nil
	} else if err != nil {
		// Error occurred while fetching row
		return false, err
	}

	fmt.Println("Showing notif:", name, ":", message)
	// update the form in memory
	a.Name = name
	a.Message = message
	a.Amount = amount
	a.Currency = currency
	a.MediaURL = media_url
	a.USDAmount = usd_amount
	a.Refresh = getRefreshFromUSDAmount(usd_amount, media_url)
	a.DisplayToggle = "display: block;"

	// Remove fetched entry from queue table
	_, err = db.Exec("DELETE FROM queue WHERE name = ? AND message = ? AND amount = ? AND currency = ?", name, message, amount, currency)
	if err != nil {
		return false, err
	}

	return true, nil
}
func getRefreshFromUSDAmount(x float64, s string) int {
	if s == "" {
		return 10
	} // if no media then return 10 second time
	minuteCost := 5
	threeMinuteCost := 10

	if x >= float64(threeMinuteCost) {
		return 3 * 60
	} else if x >= float64(minuteCost) {
		return 1 * 60
	}
	return 10
}
func returnIPPenalty(ips []string, currentDonoIP string) float64 {
	// Check if the encrypted IP matches any of the encrypted IPs in the slice of donos
	sameIPCount := 0
	for _, donoIP := range ips {
		if donoIP == currentDonoIP {
			sameIPCount++
		}
	}
	// Calculate the exponential delay factor based on the number of matching IPs
	expoAdder := 1.00
	if sameIPCount > 2 {
		expoAdder = math.Pow(1.3, float64(sameIPCount)) / 1.3
	}
	return expoAdder
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		// Redirect to the payment page if the request is not a POST request
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get the user's IP address
	ip := r.RemoteAddr

	// Get form values
	fMon := r.FormValue("mon")
	fAmount := r.FormValue("amount")
	fName := r.FormValue("name")
	fMessage := r.FormValue("message")
	fMedia := r.FormValue("media")
	fShowAmount := r.FormValue("showAmount")
	encrypted_ip := encryptIP(ip)

	// Parse and handle errors for each form value
	mon, _ := strconv.ParseBool(fMon)
	amount, err := strconv.ParseFloat(fAmount, 64)
	if (err != nil) || amount == 0 {
		if mon {
			amount = minMonero
		} else {
			amount = minSolana
		}
	}

	name := fName
	if name == "" {
		name = "Anonymous"
	}

	message := fMessage
	if message == "" {
		message = " "
	}

	media := html.EscapeString(fMedia)

	showAmount, _ := strconv.ParseBool(fShowAmount)

	var s superChat
	params := url.Values{}

	params.Add("name", name)
	params.Add("msg", message)
	params.Add("media", condenseSpaces(media))
	params.Add("amount", strconv.FormatFloat(amount, 'f', 4, 64))
	params.Add("show", strconv.FormatBool(showAmount))

	s.Amount = strconv.FormatFloat(amount, 'f', 4, 64)
	s.Name = html.EscapeString(truncateStrings(condenseSpaces(name), NameMaxChar))
	s.Message = html.EscapeString(truncateStrings(condenseSpaces(message), MessageMaxChar))
	s.Media = html.EscapeString(media)

	if mon {
		USDAmount := getUSDValue(amount, "XMR")
		payID := handleMoneroPayment(w, &s, params)
		createNewDono(1, payID, s.Name, s.Message, amount, "XMR", encrypted_ip, showAmount, USDAmount, s.Media)
	} else {
		USDAmount := getUSDValue(amount, "SOL")
		walletAddress := handleSolanaPayment(w, &s, params, name, message, amount, showAmount, media, mon)
		createNewDono(1, walletAddress, s.Name, s.Message, amount, "SOL", encrypted_ip, showAmount, USDAmount, s.Media)
	}
}

func handleSolanaPayment(w http.ResponseWriter, s *superChat, params url.Values, name_ string, message_ string, amount_ float64, showAmount_ bool, media_ string, mon_ bool) string {
	var wallet_ = createWalletSolana(name_, message_, amount_, showAmount_)
	// Get Solana address and desired balance from request
	address := wallet_.KeyPublic
	donoStr := fmt.Sprintf("%.4f", wallet_.DonoAmount)

	s.Amount = donoStr

	if wallet_.DonoName == "" {
		s.Name = "Anonymous"
		wallet_.DonoName = s.Name
	} else {
		s.Name = html.EscapeString(truncateStrings(condenseSpaces(wallet_.DonoName), NameMaxChar))
	}

	s.Media = html.EscapeString(media_)
	s.PayID = wallet_.KeyPublic
	s.Address = wallet_.KeyPublic
	s.IsSolana = !mon_

	params.Add("id", s.Address)

	s.CheckURL = params.Encode()

	tmp, _ := qrcode.Encode("solana:"+address+"?amount="+donoStr, qrcode.Low, 320)
	s.QRB64 = base64.StdEncoding.EncodeToString(tmp)

	err := payTemplate.Execute(w, s)
	if err != nil {
		fmt.Println(err)
	}

	return address
}

func handleMoneroPayment(w http.ResponseWriter, s *superChat, params url.Values) string {

	payload := strings.NewReader(`{"jsonrpc":"2.0","id":"0","method":"make_integrated_address"}`)
	req, err := http.NewRequest("POST", rpcURL, payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return "ERROR CREATING"
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return "ERROR CREATING"
	}

	resp := &rpcResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		fmt.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return "ERROR CREATING"
	}

	s.PayID = html.EscapeString(resp.Result.PaymentID)
	s.Address = html.EscapeString(resp.Result.IntegratedAddress)
	params.Add("id", resp.Result.PaymentID)
	params.Add("address", resp.Result.IntegratedAddress)
	s.CheckURL = params.Encode()

	tmp, _ := qrcode.Encode(fmt.Sprintf("monero:%s?tx_amount=%s", resp.Result.IntegratedAddress, s.Amount), qrcode.Low, 320)
	s.QRB64 = base64.StdEncoding.EncodeToString(tmp)

	err = payTemplate.Execute(w, s)
	if err != nil {
		fmt.Println(err)
	}
	return s.PayID
}

func SendSolana(senderPublicKey string, senderPrivateKey ed25519.PrivateKey, recipientAddress string, amount float64, currencyType string) {
	if currencyType == "SOL" {
		if amount > 0 {
			var feePayer, _ = types.AccountFromBytes(senderPrivateKey) // fill your private key here (u8 array)

			resp, err := c.GetLatestBlockhash(context.Background())
			if err != nil {
				log.Fatalf("failed to get recent blockhash, err: %v", err)
			}

			toPubkey := common.PublicKeyFromString(recipientAddress)
			log.Println(toPubkey)
			if err != nil {
				log.Fatalf("failed to parse recipient public key, err: %v", err)
			}

			log.Println("Public Key Payer:", feePayer.PublicKey)
			amountLamports := uint64(math.Round(amount * math.Pow10(9)))
			tx, err := types.NewTransaction(types.NewTransactionParam{
				Message: types.NewMessage(types.NewMessageParam{
					FeePayer:        feePayer.PublicKey,
					RecentBlockhash: resp.Blockhash,
					Instructions: []types.Instruction{
						system.Transfer(system.TransferParam{
							From:   feePayer.PublicKey,
							To:     toPubkey,
							Amount: amountLamports - uint64(lamportFee),
						}),
					},
				}),
				Signers: []types.Account{feePayer},
			})
			if err != nil {
				log.Fatalf("failed to build raw tx, err: %v", err)
			}
			sig, err := c.SendTransaction(context.Background(), tx)
			if err != nil {
				log.Fatalf("failed to send tx, err: %v", err)
			}
			fmt.Println(sig)
		}
	} else {
		log.Println("ERROR, tried to send", currencyType, "through SendSolana(). Not sending since XMR but continuing as everything else is fine.")
	}

}
