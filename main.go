package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	//"encoding/hex"
	"encoding/json"
	"fmt"
	//	"github.com/davecgh/go-spew/spew"
	"github.com/gabstv/go-monero/walletrpc"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"shadowchat/utils"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
	//"github.com/realclientip/realclientip-go"
)

const username = "admin"

var pending_donos []utils.SuperChat
var ip_requests []string

var USDMinimum float64 = 5
var MediaMin float64 = 0.025 // Currently unused
var MessageMaxChar int = 250
var NameMaxChar int = 25
var starting_port int = 28088

var host_url string = "https://ferret.cash/"

var addressSliceSolana []utils.AddressSolana

var checked string = ""
var killDono = 35.00 * time.Minute // hours it takes for a dono to be unfulfilled before it is no longer checked.
var indexTemplate *template.Template
var overflowTemplate *template.Template
var tosTemplate *template.Template
var registerTemplate *template.Template
var donationTemplate *template.Template
var payTemplate *template.Template

var alertTemplate *template.Template
var accountPayTemplate *template.Template
var billPayTemplate *template.Template
var progressbarTemplate *template.Template
var userOBSTemplate *template.Template
var viewTemplate *template.Template

var loginTemplate *template.Template
var footerTemplate *template.Template
var incorrectLoginTemplate *template.Template
var userTemplate *template.Template
var cryptoSettingsTemplate *template.Template
var logoutTemplate *template.Template
var incorrectPasswordTemplate *template.Template
var baseCheckingRate = 25

var eth_transactions []utils.Transfer

var minSolana, minMonero, minEthereum, minPaint, minHex, minPolygon, minBusd, minShib, minUsdc, minTusd, minWbtc, minPnk float64 // Global variables to hold minimum values required to equal the global value.
var minDonoValue float64 = 5.0

var solWallets = map[int]utils.SolWallet{}

var inviteCodeMap = map[string]utils.InviteCode{}

var PublicRegistrationsEnabled = false

var ServerMinMediaDono = 5
var ServerMediaEnabled = true

var xmrWallets = [][]int{}

var globalUsers = map[int]utils.User{}
var pendingGlobalUsers = map[int]utils.PendingUser{}

var db *sql.DB
var userSessions = make(map[string]int)
var amountNeeded = 1000.00
var amountSent = 200.00
var donosMap = make(map[int]utils.Dono) // initialize an empty map

var a utils.AlertPageData
var pb utils.ProgressbarData
var obsData utils.OBSDataStruct

var prices utils.CryptoPrice

var pbMessage = "Stream Tomorrow"

type Route_ struct {
	Path    string
	Handler func(http.ResponseWriter, *http.Request)
}

var routes_ []Route_

// Define a new template that only contains the table content
var tableTemplate = template.Must(template.New("table").Parse(`
	{{range .}}
	<tr id="{{.ID}}">
                    <td>
                        <button onclick="replayDono('{{.ID}}')">Replay</button>
                    </td>
                    <td>{{.UpdatedAt.Format "15:04:05 01-02-2006"}}</td>
                    <td>{{.Name}}</td>
                    <td>{{.Message}}</td>
                    <td>{{.MediaURL}}</td>
                    <td>${{.USDAmount}}</td>
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

	_, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}

func checkLoggedInAdmin(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		return false
	}

	if user.Username == "admin" {
		return true
	} else {
		return false
	}
}

func generateMoreInviteCodes(codeAmount int) {
	newCodes := utils.GenerateUniqueCodes(codeAmount)
	for _, code := range newCodes {
		err := createNewInviteCode(code.Value, code.Active)
		if err != nil {
			log.Println("createNewInviteCode() error:", err)
		}
	}
	inviteCodeMap = utils.AddInviteCodes(inviteCodeMap, newCodes)
}

// Handler function for the "/donations" endpoint
func donationsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("donationsHandler Called")

	cookie, err := r.Cookie("session_token")
	if err != nil {
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		return
	}
	// Fetch the latest data from your database or other data source

	// Retrieve data from the donos table
	rows, err := db.Query("SELECT * FROM donos WHERE fulfilled = 1 AND amount_sent != '0.0' ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the data
	var donos []utils.Dono
	for rows.Next() {
		var dono utils.Dono
		var name, message, address, currencyType, encryptedIP, amountToSend, amountSent, mediaURL sql.NullString
		var usdAmount sql.NullFloat64
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
		dono.AmountToSend = amountToSend.String
		dono.AmountSent = amountSent.String
		dono.CurrencyType = currencyType.String
		dono.AnonDono = anonDono.Bool
		dono.Fulfilled = fulfilled.Bool
		dono.EncryptedIP = encryptedIP.String
		dono.USDAmount = usdAmount.Float64
		dono.MediaURL = mediaURL.String
		if dono.UserID == user.UserID {
			if s, err := strconv.ParseFloat(dono.AmountSent, 64); err == nil {
				if s > 0 {
					donos = append(donos, dono)
				}
			}
		}
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

	go startWallets()

	time.Sleep(5 * time.Second)
	log.Println("Starting server")

	setupRoutes()

	time.Sleep(2 * time.Second)
	// Schedule a function to run fetchExchangeRates every three minutes
	go fetchExchangeRates()
	go checkDonos()
	go checkPendingAccounts()
	go checkBillingAccounts()

	go checkAccountBillings()

	a.Refresh = 10
	pb.Refresh = 1
	obsData = getObsData(db, 1)
	inviteCodeMap = getAllCodes()
	setServerVars()

	//go createTestDono(2, "Big Bob", "XMR", "This Cruel Message is Bob's Test message! Test message! Test message! Test message! Test message! Test message! Test message! Test message! Test message! Test message! ", "50", 100, "https://www.youtube.com/watch?v=6iseNlvH2_s")
	// go createTestDono("Medium Bob", "XMR", "Hey it's medium Bob ", 0.1, 3, "https://www.youtube.com/watch?v=6iseNlvH2_s")

	err = http.ListenAndServe(":8900", nil)
	if err != nil {
		panic(err)
	}

}

func updateCryptosHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var updateRequest utils.UpdateCryptosRequest
	err = json.Unmarshal(body, &updateRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := strconv.Atoi(updateRequest.UserID)

	log.Println(userID, user.UserID)

	if userID == user.UserID {
		user.CryptosEnabled = mapToCryptosEnabled(updateRequest.SelectedCryptos)
		if user.CryptosEnabled.XMR && !user.WalletUploaded {
			user.CryptosEnabled.XMR = false
		}
		log.Println(user.CryptosEnabled)
		err = updateUser(user)
		if err != nil {
			log.Println(err)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func mapToCryptosEnabled(selectedCryptos map[string]bool) utils.CryptosEnabled {
	// Create a new instance of the CryptosEnabled struct
	cryptosEnabled := utils.CryptosEnabled{}

	// Set each field of the CryptosEnabled struct based on the corresponding value in the map
	cryptosEnabled.XMR = selectedCryptos["monero"]
	cryptosEnabled.SOL = selectedCryptos["solana"]
	cryptosEnabled.ETH = selectedCryptos["ethereum"]
	cryptosEnabled.PAINT = selectedCryptos["paint"]
	cryptosEnabled.HEX = selectedCryptos["hex"]
	cryptosEnabled.MATIC = selectedCryptos["matic"]
	cryptosEnabled.BUSD = selectedCryptos["busd"]
	cryptosEnabled.SHIB = selectedCryptos["shiba_inu"]
	cryptosEnabled.PNK = selectedCryptos["pnk"]

	// Return the populated CryptosEnabled struct
	return cryptosEnabled
}
func setupRoutes() {
	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/style.css")
	})

	http.HandleFunc("/xmr.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/xmr.svg")
	})

	http.HandleFunc("/bignumber.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/js/bignumber.js")
	})

	http.HandleFunc("/checkmark.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/xmr.png")
	})

	http.HandleFunc("/fcash.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/fcash.png")
	})

	http.HandleFunc("/indexfcash.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/indexfcash.png")
	})

	http.HandleFunc("/loader.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/loader.svg")
	})

	http.HandleFunc("/eth.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/eth.svg")
	})

	http.HandleFunc("/sol.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/sol.svg")
	})

	http.HandleFunc("/busd.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/busd.svg")
	})

	http.HandleFunc("/hex.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/hex.svg")
	})

	http.HandleFunc("/matic.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/matic.svg")
	})

	http.HandleFunc("/paint.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/paint.svg")
	})

	http.HandleFunc("/pnk.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/pnk.svg")
	})

	http.HandleFunc("/shiba_inu.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/shiba_inu.svg")
	})

	http.HandleFunc("/tether.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/tether.svg")
	})

	http.HandleFunc("/usdc.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/usdc.svg")
	})

	http.HandleFunc("/wbtc.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/wbtc.svg")
	})

	http.Handle("/media/", http.StripPrefix("/media/", http.FileServer(http.Dir("web/obs/media/"))))
	http.Handle("/users/", http.StripPrefix("/users/", http.FileServer(http.Dir("users/"))))

	routes_ = []Route_{
		{"/updatecryptos", updateCryptosHandler},
		{"/update-links", updateLinksHandler},
		{"/check_donation_status/", checkDonationStatusHandler},
		{"/donations", donationsHandler},
		{"/", indexHandler},
		{"/termsofservice", tosHandler},
		{"/pay", paymentHandler},
		{"/alert", alertOBSHandler},
		{"/viewdonos", viewDonosHandler},
		{"/replaydono", replayDonoHandler},
		{"/progressbar", progressbarOBSHandler},
		{"/login", loginHandler},
		{"/incorrect_login", incorrectLoginHandler},
		{"/user", userHandler},
		{"/userobs", userOBSHandler},
		{"/logout", logoutHandler},
		{"/changepassword", changePasswordHandler},
		{"/changeuser", changeUserHandler},
		{"/register", registerUserHandler},
		{"/newaccount", newAccountHandler},
		{"/overflow", overflowHandler},
		{"/billing", accountBillingHandler},
		{"/changeusermonero", changeUserMoneroHandler},
		{"/usermanager", allUsersHandler},
		{"/refresh", refreshHandler},
		{"/toggleUserRegistrations", toggleUserRegistrationsHandler},
		{"/generatecodes", generateCodesHandler},
		{"/cryptosettings", cryptoSettingsHandler},
	}

	for _, route_ := range routes_ {
		http.HandleFunc(route_.Path, logging(route_.Handler))
	}

	indexTemplate, _ = template.ParseFiles("web/index.html")

	overflowTemplate, _ = template.ParseFiles("web/overflow.html")
	tosTemplate, _ = template.ParseFiles("web/tos.html")
	registerTemplate, _ = template.ParseFiles("web/new_account.html")
	donationTemplate, _ = template.ParseFiles("web/donation.html")
	footerTemplate, _ = template.ParseFiles("web/footer.html")
	payTemplate, _ = template.ParseFiles("web/pay.html")
	alertTemplate, _ = template.ParseFiles("web/alert.html")
	accountPayTemplate, _ = template.ParseFiles("web/accountpay.html")

	billPayTemplate, _ = template.ParseFiles("web/billpay.html")

	userOBSTemplate, _ = template.ParseFiles("web/obs/settings.html")
	progressbarTemplate, _ = template.ParseFiles("web/obs/progressbar.html")

	loginTemplate, _ = template.ParseFiles("web/login.html")
	incorrectLoginTemplate, _ = template.ParseFiles("web/incorrect_login.html")
	userTemplate, _ = template.ParseFiles("web/user.html")
	cryptoSettingsTemplate, _ = template.ParseFiles("web/cryptoselect.html")

	logoutTemplate, _ = template.ParseFiles("web/logout.html")
	incorrectPasswordTemplate, _ = template.ParseFiles("web/password_change_failed.html")
}

func clearRecentIPS(ip string) {
	for {
		ip_requests = ip_requests[:0]
		time.Sleep(5 * time.Minute)
	}
}

func CheckRecentIPRequests(ip string) int {
	matching_ips := 0
	for _, ip_ := range ip_requests {
		err := bcrypt.CompareHashAndPassword([]byte(ip_), []byte(ip))
		if err == nil {
			matching_ips++
			if matching_ips == 80 {
				ip_requests = append(ip_requests, encryptIP(ip))
				return matching_ips
			}
		}
	}
	ip_requests = append(ip_requests, encryptIP(ip))
	return matching_ips
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/overflow" && r.URL.Path != "/progressbar" && r.URL.Path != "/donations" && r.URL.Path != "/check_donation_status" && r.URL.Path != "/replaydono" && r.URL.Path != "/viewdonos" {
			ip := getIPAddress(r)
			matchingIP := CheckRecentIPRequests(ip)
			if matchingIP >= 200 {
				http.Redirect(w, r, "/overflow", http.StatusSeeOther)
				return
			}
		}
		f(w, r)
	}
}

func replayDonoHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, valid := getLoggedInUser(w, r)

	var donation utils.Donation
	err := json.NewDecoder(r.Body).Decode(&donation)
	if err != nil {
		fmt.Printf("Error decoding JSON")
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}

	// Process the donation information as needed
	fmt.Printf("Received donation replay: %+v\n", donation)

	if valid {
		replayDono(donation, user.UserID)
	} else {
		http.Error(w, "Invalid donation trying to be replayed", http.StatusBadRequest)
		return
	}

	// Send response indicating success
	w.WriteHeader(http.StatusOK)
}

func startWallets() {
	printUserColumns()
	users, err := getAllUsers()
	if err != nil {
		log.Fatalf("startWallet() error:", err)
	}

	for _, user := range users {
		log.Println("Checking user:", user.Username, "User ID:", user.UserID, "User billing data enabled:", user.BillingData.Enabled)
		if user.BillingData.Enabled {
			log.Println("User valid", user.UserID, "User eth_address:", globalUsers[user.UserID].EthAddress)
			if user.WalletUploaded {
				log.Println("Monero wallet uploaded")
				xmrWallets = append(xmrWallets, []int{user.UserID, starting_port})
				go startMoneroWallet(starting_port, user.UserID, user)
				starting_port++

			} else {
				log.Println("Monero wallet not uploaded")
			}
		} else {
			log.Println("startWallets() User not valid")
		}
	}

	fmt.Println("startWallet() starting monitoring of solana addresses.")
	for _, user := range users {
		solWallets[user.UserID] = utils.SolWallet{
			Address: user.SolAddress,
			Amount:  0.00,
		}
	}

	utils.SetSolWallets(solWallets)
	go utils.StartMonitoringSolana()
}

func checkValidSubscription(DateEnabled time.Time) bool {
	oneMonthAhead := DateEnabled.AddDate(0, 1, 0)
	if oneMonthAhead.After(time.Now().UTC()) {
		log.Println("User valid")
		return true
	}
	log.Println("checkValidSubscription() User not valid")
	return false
}

func getLoggedInUser(w http.ResponseWriter, r *http.Request) (utils.User, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return utils.User{}, false // Return an instance of utils.User with empty/default values
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		return utils.User{}, false // Return an instance of utils.User with empty/default values
	}

	return user, true
}

func allUsersHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if user.Username == "admin" {

		// Define the data to be passed to the HTML template
		data := struct {
			Title            string
			RegistrationOpen bool
			Users            map[int]utils.User
			InviteCodes      map[string]utils.InviteCode
		}{
			Title:            "Users Dashboard",
			RegistrationOpen: PublicRegistrationsEnabled,
			Users:            globalUsers,
			InviteCodes:      inviteCodeMap,
		}

		// Parse the HTML template and execute it with the data
		tmpl, err := template.ParseFiles("web/view_users.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

func generateCodesHandler(w http.ResponseWriter, r *http.Request) {
	if checkLoggedInAdmin(w, r) {
		generateMoreInviteCodes(5)
		http.Redirect(w, r, "/usermanager", http.StatusSeeOther)
		allUsersHandler(w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

}

func toggleUserRegistrationsHandler(w http.ResponseWriter, r *http.Request) {

	if checkLoggedInAdmin(w, r) {
		PublicRegistrationsEnabled = !PublicRegistrationsEnabled
		http.Redirect(w, r, "/usermanager", http.StatusSeeOther)
		allUsersHandler(w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if checkLoggedInAdmin(w, r) {
		user, _ := getUserByUsernameCached(r.FormValue("username"))
		renewUserSubscription(user)
	}
	allUsersHandler(w, r)
}

func updateEnabledDate(userID int) error {
	// Get the current time
	now := time.Now()

	// Update the user's enabled date in the database
	_, err := db.Exec("UPDATE users SET date_enabled=? WHERE id=?", now, userID)
	if err != nil {
		return err
	}

	return nil
}

func getAllCodes() map[string]utils.InviteCode {

	rows, err := db.Query("SELECT * FROM invites")
	if err != nil {
		log.Println(err)
		return inviteCodeMap
	}
	defer rows.Close()

	for rows.Next() {
		var ic utils.InviteCode

		err = rows.Scan(&ic.Value, &ic.Active)

		if err != nil {
			log.Println(err)
			return inviteCodeMap
		}
		inviteCodeMap[ic.Value] = ic
	}

	return inviteCodeMap

}

func getAllUsers() ([]utils.User, error) {
	var users []utils.User
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user utils.User
		var links, donoGIF, donoSound, alertURL, defaultCrypto, cryptosEnabled sql.NullString

		err = rows.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
			&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
			&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound,
			&alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)

		if err != nil {
			return nil, err
		}

		user.Links = links.String
		if !links.Valid {
			user.Links = ""
		}

		user.DonoGIF = donoGIF.String
		if !donoGIF.Valid {
			user.DonoGIF = "default.gif"
		}

		user.DonoSound = donoSound.String
		if !donoSound.Valid {
			user.DonoSound = "default.mp3"
		}

		user.DefaultCrypto = defaultCrypto.String
		if !defaultCrypto.Valid {
			user.DefaultCrypto = ""
		}

		user.AlertURL = alertURL.String
		if !alertURL.Valid {
			user.AlertURL = utils.GenerateUniqueURL()
		}

		ce := utils.CryptosEnabled{
			XMR:   true,
			SOL:   true,
			ETH:   false,
			PAINT: false,
			HEX:   true,
			MATIC: false,
			BUSD:  true,
			SHIB:  false,
			PNK:   true,
		}

		user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String)
		if !cryptosEnabled.Valid {
			log.Println("user cryptos enabled not fixed")
			user.CryptosEnabled = ce
		}

		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	billings, err := getAllBilling()
	if err != nil {
		return nil, err
	}

	billingMap := make(map[int]utils.BillingData)
	for _, billing := range billings {
		billingMap[billing.UserID] = billing
	}

	for i := range users {
		billing, ok := billingMap[users[i].UserID]
		if ok {
			users[i].BillingData = billing
			globalUsers[users[i].UserID] = users[i]
		}
	}

	return users, nil
}

func getAllBilling() ([]utils.BillingData, error) {
	var billings []utils.BillingData
	rows, err := db.Query("SELECT * FROM billing")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var billingData utils.BillingData
		err = rows.Scan(&billingData.BillingID, &billingData.UserID, &billingData.AmountThisMonth, &billingData.AmountTotal, &billingData.Enabled, &billingData.NeedToPay, &billingData.ETHAmount, &billingData.XMRAmount, &billingData.XMRPayID, &billingData.CreatedAt, &billingData.UpdatedAt)
		if err != nil {
			log.Println(err)
		}

		fmt.Println("UserID: ", billingData.UserID)
		fmt.Println("Amount This Month: ", billingData.AmountThisMonth)
		fmt.Println("Amount Total: ", billingData.AmountTotal)
		fmt.Println("Enabled: ", billingData.Enabled)
		fmt.Println("Need To Pay: ", billingData.NeedToPay)
		fmt.Println("Created At: ", billingData.CreatedAt)
		fmt.Println("Updated At: ", billingData.UpdatedAt)

		billings = append(billings, billingData)
	}

	if err = rows.Err(); err != nil {
		log.Println(err)
		return nil, err
	}

	return billings, nil
}

func getActiveETHUsers(db *sql.DB) ([]*utils.User, error) {
	var users []*utils.User

	// Define the query to select the active ETH users
	query := `SELECT * FROM users WHERE eth_address != ''`

	// Execute the query
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var user utils.User
		err = rows.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress, &user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono, &user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &user.Links, &user.DonoGIF, &user.DonoSound, &user.AlertURL, &user.WalletUploaded, &user.DateEnabled)
		if err != nil {
			return nil, err
		}

		oneMonthAhead := user.DateEnabled.AddDate(0, 1, 0)
		if oneMonthAhead.After(time.Now().UTC()) {
			users = append(users, &user)
		}
	}
	return users, nil
}

func getActiveXMRUsers(db *sql.DB) ([]*utils.User, error) {
	var users []*utils.User

	// Define the query to select the active XMR users
	query := `SELECT * FROM users WHERE wallet_uploaded = ?`

	// Execute the query
	rows, err := db.Query(query, true)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var user utils.User
		err = rows.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress, &user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono, &user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &user.Links, &user.DonoGIF, &user.DonoSound, &user.AlertURL, &user.WalletUploaded, &user.DateEnabled)
		if err != nil {
			return nil, err
		}

		oneMonthAhead := user.DateEnabled.AddDate(0, 1, 0)
		if oneMonthAhead.After(time.Now().UTC()) {
			users = append(users, &user)
		}

	}
	return users, nil
}

func getUserCryptosEnabled(user utils.User) (utils.User, error) {

	user.CryptosEnabled.XMR = false
	user.CryptosEnabled.SOL = false
	user.CryptosEnabled.ETH = false
	user.CryptosEnabled.PAINT = true
	user.CryptosEnabled.HEX = false
	user.CryptosEnabled.MATIC = true
	user.CryptosEnabled.BUSD = false
	user.CryptosEnabled.SHIB = true
	user.CryptosEnabled.PNK = false

	return user, nil

}

// get links for a user
func getUserLinks(user utils.User) ([]utils.Link, error) {
	if user.Links == "" {
		// Insert default links for the user
		defaultLinks := []utils.Link{
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

	var links []utils.Link
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
	setMinDonos()
}

func createTestDono(user_id int, name string, curr string, message string, amount string, usdAmount float64, media_url string) {
	valid, media_url_ := checkDonoForMediaUSDThreshold(media_url, usdAmount)

	if valid == false {
		media_url_ = ""
	}

	log.Println("TESTING DONO IN FIVE SECONDS")
	time.Sleep(5 * time.Second)
	log.Println("TESTING DONO NOW")
	err := createNewQueueEntry(db, user_id, "TestAddress", name, message, amount, curr, usdAmount, media_url_)
	if err != nil {
		panic(err)
	}
	addDonoToDonoBar(amount, curr, user_id)
}

func replayDono(donation utils.Donation, userID int) {
	valid, media_url_ := checkDonoForMediaUSDThreshold(donation.DonationMedia, convertToFloat64(donation.USDValue))

	if valid == false {
		media_url_ = ""
	}

	err := createNewQueueEntry(db, userID, "ReplayAddress", donation.DonationName, donation.DonationMessage, donation.AmountSent, donation.Crypto, convertToFloat64(donation.USDValue), media_url_)
	if err != nil {
		panic(err)
	}
}

func convertToFloat64(value string) float64 {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		panic(err)
	}
	return f
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

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	cookie = cookie

	// Retrieve data from the donos table
	rows, err := db.Query("SELECT * FROM donos WHERE fulfilled = 1 AND amount_sent != 0 ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the data
	var donos []utils.Dono
	for rows.Next() {
		var dono utils.Dono
		var name, amountToSend, amountSent, message, address, currencyType, encryptedIP, mediaURL sql.NullString
		var usdAmount sql.NullFloat64
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
		dono.AmountToSend = amountToSend.String
		dono.AmountSent = amountSent.String
		dono.CurrencyType = currencyType.String
		dono.AnonDono = anonDono.Bool
		dono.Fulfilled = fulfilled.Bool
		dono.EncryptedIP = encryptedIP.String
		dono.USDAmount = usdAmount.Float64
		dono.MediaURL = mediaURL.String
		if dono.UserID == user.UserID {
			if s, err := strconv.ParseFloat(dono.AmountSent, 64); err == nil {
				if s > 0 {
					donos = append(donos, dono)
				}
			}
		}
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
			return donos[i].USDAmount < donos[j].USDAmount
		})
	}

	// Send the data to the template
	tpl, err := template.ParseFiles("web/view_donos.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := utils.ViewDonosData{
		Username: user.Username,
		Donos:    donos,
	}
	tpl.Execute(w, data)
}

func setUserMinDonos(user utils.User) utils.User {
	var err error
	user.MinSol, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Solana)), 64)
	user.MinEth, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Ethereum)), 64)
	user.MinXmr, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Monero)), 64)
	user.MinPaint, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Paint)), 64)
	user.MinHex, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Hexcoin)), 64)
	user.MinMatic, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Polygon)), 64)
	user.MinBusd, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.BinanceUSD)), 64)
	user.MinShib, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.ShibaInu)), 64)
	user.MinUsdc, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono))), 64)
	user.MinTusd, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono))), 64)
	user.MinWbtc, _ = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.WBTC)), 64)
	user.MinPnk, err = strconv.ParseFloat(fmt.Sprintf("%.5f", (float64(user.MinDono)/prices.Kleros)), 64)
	if err != nil {
		log.Println("setUserMinDonos() err:", err)
	}

	return user
}

func setMinDonos() {
	for i := range globalUsers {
		globalUsers[i] = setUserMinDonos(globalUsers[i])
	}
}

func fetchExchangeRates() {
	for {
		// Fetch the exchange rate data from the API
		var err error
		prices, err = utils.GetCryptoPrices()
		if err != nil {
			log.Println(err)
		} else {
			setMinDonos()
		}

		time.Sleep(80 * time.Second)
	}

}

func createNewEthDono(name string, message string, mediaURL string, amountNeeded float64, cryptoCode string, encrypted_ip string) utils.SuperChat {
	new_dono := utils.CreatePendingDono(name, message, mediaURL, amountNeeded, cryptoCode, encrypted_ip)
	pending_donos = utils.AppendPendingDono(pending_donos, new_dono)

	return new_dono
}

func startMoneroWallet(portInt, userID int, user utils.User) {
	portID := getPortID(xmrWallets, userID)
	found := true

	if portID == -100 {
		found = false
	}

	portStr := strconv.Itoa(portID)

	if found {
		fmt.Println("Port ID for user", userID, "is", portID)
	} else {
		fmt.Println("Port ID not found for user", userID)
		portStr = strconv.Itoa(portInt)
	}

	cmd := exec.Command("./start_xmr_wallet.sh", portStr, strconv.Itoa(userID))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		log.Println("Error running command:", err)
		walletRunning := CheckMoneroPort(userID)
		if walletRunning {
			user.WalletUploaded = true
			user.WalletPending = false
		} else {
			user.WalletUploaded = false
			user.WalletPending = false
		}
		updateUser(user)
		return
	}

	_ = walletrpc.New(walletrpc.Config{
		Address: "http://127.0.0.1:" + strconv.Itoa(portInt) + "/json_rpc",
	})

	fmt.Println("Done starting monero wallet for", portStr, userID)
	user.WalletUploaded = true
	user.WalletPending = true
	updateUser(user)
}

func CheckMoneroPort(userID int) bool {
	payload := strings.NewReader(`{"jsonrpc":"2.0","id":"0","method":"make_integrated_address"}`)
	portID := getPortID(xmrWallets, userID)

	found := true
	if portID == -100 {
		return false
	}

	if found {
		fmt.Println("Port ID for user", userID, "is", portID)
	} else {
		fmt.Println("Port ID not found for user", userID)
	}

	rpcURL_ := "http://127.0.0.1:" + strconv.Itoa(portID) + "/json_rpc"

	req, err := http.NewRequest("POST", rpcURL_, payload)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}

	resp := &utils.RPCResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return false
	}

	return true
}

func stopMoneroWallet(user utils.User) {
	portID := getPortID(xmrWallets, user.UserID)

	found := true
	if portID == -100 {
		found = false
	}

	if !found {
		fmt.Println("Port ID not found for user", user.UserID)
		return
	}

	portStr := strconv.Itoa(portID)

	cmd := exec.Command("monero/monero-wallet-rpc", "--rpc-bind-port", portStr, "--command", "stop_wallet")

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
		log.Println("Checking pending wallets for successful starting")
		for _, u_ := range globalUsers {
			if u_.WalletUploaded && u_.WalletPending {
				u_.WalletPending = CheckMoneroPort(u_.UserID)
				if !u_.WalletPending {
					updateUser(u_)
				}
			}
		}

		log.Println("Checking donos via checkDonos()")
		fulfilledDonos := checkUnfulfilledDonos()
		if len(fulfilledDonos) > 0 {
			fmt.Println("Fulfilled Donos:")
		}

		for _, dono := range fulfilledDonos {
			fmt.Println(dono)
			user := globalUsers[dono.UserID]
			if user.BillingData.AmountTotal >= 500 {
				user.BillingData.AmountThisMonth += dono.USDAmount
			} else if user.BillingData.AmountTotal+dono.USDAmount >= 500 {
				user.BillingData.AmountThisMonth += user.BillingData.AmountTotal + dono.USDAmount - 500
			}
			user.BillingData.AmountTotal += dono.USDAmount
			updateUser(user)

			err := createNewQueueEntry(db, dono.UserID, dono.Address, dono.Name, dono.Message, dono.AmountSent, dono.CurrencyType, dono.USDAmount, dono.MediaURL)
			if err != nil {
				panic(err)
			}

		}
		time.Sleep(time.Duration(25) * time.Second)
	}
}

func getAdminETHAdd() string {
	user, validUser := getUserByUsernameCached(username)

	if !validUser {
		return ""
	}

	return user.EthAddress
}

func checkBillingAccounts() {
	for {
		tMapGenerated := false
		transactionMap := make(map[string]utils.Transfer)

		for _, user := range globalUsers {

			if user.BillingData.NeedToPay {

				xmrFl, _ := getXMRBalance(user.BillingData.XMRPayID, 1)
				xmrSent, _ := utils.StandardizeFloatToString(xmrFl)
				xmrSentStr, _ := utils.StandardizeString(xmrSent)
				if user.BillingData.XMRAmount == xmrSentStr {
					renewUserSubscription(user)
					continue
				}

				adminETHAdd := getAdminETHAdd()

				if !tMapGenerated { //Generate Map from transaction slice
					for _, transaction := range eth_transactions {
						hash := utils.GetTransactionAmount(transaction)
						standard_hash, _ := utils.StandardizeString(hash)
						transactionMap[standard_hash] = transaction
					}
					tMapGenerated = true
				}

				valueToCheck, _ := utils.StandardizeString(user.BillingData.ETHAmount)
				transaction, ok := transactionMap[valueToCheck]
				if ok {
					tN := utils.GetTransactionToken(transaction)
					if tN == "ETH" && transaction.To == adminETHAdd {
						renewUserSubscription(user)
						continue
					}
				}
			}
		}
		time.Sleep(time.Duration(30) * time.Second)
	}
}

func renewUserSubscription(user utils.User) {
	user.BillingData.Enabled = true
	user.BillingData.AmountThisMonth = 0.00
	user.BillingData.AmountNeeded = 0.00
	user.BillingData.NeedToPay = false
	user.BillingData.UpdatedAt = time.Now().UTC()
	updateUser(user)
}

func checkPendingAccounts() {
	for {

		for _, transaction := range eth_transactions {
			tN := utils.GetTransactionToken(transaction)
			if tN == "ETH" && transaction.To == getAdminETHAdd() {
				valueStr := fmt.Sprintf("%.18f", transaction.Value)

				for _, user := range pendingGlobalUsers {
					if user.ETHNeeded == valueStr {
						err := createNewUserFromPending(user)
						if err != nil {
							log.Println("Error marking payment as complete:", err)
						} else {
							log.Println("Payment marked as complete for:", user.Username)
						}
					}
				}
			}
		}

		for _, user := range pendingGlobalUsers {
			xmrFl, _ := getXMRBalance(user.XMRPayID, 1)
			xmrSent, _ := utils.StandardizeFloatToString(xmrFl)

			log.Println("XMR sent:", xmrSent)
			xmrSentStr, _ := utils.ConvertStringTo18DecimalPlaces(xmrSent)
			log.Println("XMR sent str:", xmrSentStr)
			log.Println("XMRNeeded str:", user.XMRNeeded)
			if user.XMRNeeded == xmrSentStr {
				err := createNewUserFromPending(user)
				if err != nil {
					log.Println("Error marking payment as complete:", err)
				} else {
					log.Println("Payment marked as complete for:", user.Username)
				}
			}
		}

		time.Sleep(time.Duration(25) * time.Second)
	}
}

func checkAccountBillings() {
	for {
		for _, user := range globalUsers {
			if user.BillingData.Enabled {
				// check if the updated amount is from the current or previous month
				now := time.Now()
				updatedMonth := user.BillingData.UpdatedAt.Month()
				currentMonth := now.Month()
				if user.BillingData.AmountTotal >= 500 {

					if updatedMonth == currentMonth {
						continue
					} else if now.Day() >= 4 {
						// the updated amount is from an earlier month, so disable billing
						user.BillingData.Enabled = false
						user.BillingData.NeedToPay = true
						user.BillingData.AmountNeeded = math.Round(user.BillingData.AmountThisMonth*0.03*100) / 100

						xmrNeeded := getXMRAmountInUSD(user.BillingData.AmountNeeded)
						ethNeeded := getETHAmountInUSD(user.BillingData.AmountNeeded)

						PayID, PayAddress := getNewAccountXMR()
						user.BillingData.XMRPayID = PayID
						user.BillingData.XMRAddress = PayAddress
						user.BillingData.XMRAmount = xmrNeeded
						user.BillingData.ETHAmount = ethNeeded

						fmt.Printf("Disabling billing for user %d\n", user.UserID)
					} else {
						user.BillingData.NeedToPay = true
						user.BillingData.Enabled = true
					}
				} else {
					renewUserSubscription(user)
				}
			}
		}
		time.Sleep(time.Duration(12) * time.Hour)
	}
}

func getUSDValue(as float64, c string) float64 {
	usdVal := 0.00

	priceMap := map[string]float64{
		"XMR":   prices.Monero,
		"SOL":   prices.Solana,
		"ETH":   prices.Ethereum,
		"PAINT": prices.Paint,
		"HEX":   prices.Hexcoin,
		"MATIC": prices.Polygon,
		"BUSD":  prices.BinanceUSD,
		"SHIB":  prices.ShibaInu,
		"PNK":   prices.Kleros,
	}

	if price, ok := priceMap[c]; ok {
		usdVal = as * price
	} else {
		usdVal = 1.00
		return usdVal
	}
	usdValStr := fmt.Sprintf("%.2f", usdVal)      // format usdVal as a string with 2 decimal points
	usdVal, _ = strconv.ParseFloat(usdValStr, 64) // convert the string back to a float

	return usdVal
}

func addDonoToDonoBar(as, c string, userID int) {
	f, err := strconv.ParseFloat(as, 64)
	usdVal := getUSDValue(f, c)
	obsData, err := getOBSDataByUserID(userID)
	pb.Sent = obsData.Sent
	pb.Needed = obsData.Needed
	pb.Message = obsData.Message
	pb.Sent += usdVal

	sent, err := strconv.ParseFloat(fmt.Sprintf("%.2f", pb.Sent), 64)
	if err != nil {
		// handle the error here
		log.Println("Error converting to cents: ", err)
	}
	pb.Sent = sent

	amountSent = pb.Sent

	err = updateObsData(db, userID, obsData.FilenameGIF, obsData.FilenameMP3, "alice", pb)

	if err != nil {
		log.Println("Error: ", err)
	}
}

func formatMediaURL(media_url string) string {
	isValid, timecode, properLink := isYouTubeLink(media_url)
	log.Println(isValid, timecode, properLink)

	embedLink := ""
	if isValid {
		videoID := extractVideoID(properLink)
		embedLink = fmt.Sprintf(videoID)
	}
	return embedLink
}

func createNewQueueEntry(db *sql.DB, user_id int, address string, name string, message string, amount string, currency string, dono_usd float64, media_url string) error {
	f, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		panic(err)
	}
	// Round the amount to 6 decimal places if it has more than 6 decimal places
	if math.Abs(f-math.Round(f)) >= 0.000001 {
		f = math.Round(f*1e6) / 1e6
	}

	embedLink := formatMediaURL(media_url)

	_, err = db.Exec(`
		INSERT INTO queue (name, message, amount, currency, usd_amount, media_url, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, name, message, amount, currency, dono_usd, embedLink, user_id)
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

func createNewDono(user_id int, dono_address string, dono_name string, dono_message string, amount_to_send string, currencyType string, encrypted_ip string, anon_dono bool, dono_usd float64, media_url string) int64 {
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

	amount_to_send, _ = utils.StandardizeString(amount_to_send)

	// Execute the SQL INSERT statement
	result, err := db.Exec(`
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
    `, user_id, dono_address, dono_name, dono_message, amount_to_send, "0.0", currencyType, anon_dono, false, encrypted_ip, createdAt, createdAt, dono_usd, media_url_)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	// Get the id of the newly created dono
	id, err := result.LastInsertId()
	if err != nil {
		log.Println(err)
		panic(err)
	}

	return id
}

func clearEncryptedIP(dono *utils.Dono) {
	dono.EncryptedIP = ""
}

func encryptIP(ip string) string {
	hashedIP, _ := bcrypt.GenerateFromPassword([]byte(ip), bcrypt.MinCost)
	return string(hashedIP)
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

func updatePendingDonos() {

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
	for rows.Next() {
		var dono utils.Dono
		var tmpAmountToSend sql.NullString
		var tmpAmountSent sql.NullString
		var tmpUSDAmount sql.NullFloat64
		var tmpMediaURL sql.NullString

		err := rows.Scan(&dono.ID, &dono.UserID, &dono.Address, &dono.Name, &dono.Message, &tmpAmountToSend, &tmpAmountSent, &dono.CurrencyType, &dono.AnonDono, &dono.Fulfilled, &dono.EncryptedIP, &dono.CreatedAt, &dono.UpdatedAt, &tmpUSDAmount, &tmpMediaURL)
		if err != nil {
			panic(err)
		}

		if tmpUSDAmount.Valid {
			dono.USDAmount = tmpUSDAmount.Float64
		} else {
			dono.USDAmount = 0.0
		}

		if tmpAmountToSend.Valid {
			dono.AmountToSend = tmpAmountToSend.String
		} else {
			dono.AmountToSend = "0.0"
		}

		if tmpAmountSent.Valid {
			dono.AmountSent = tmpAmountSent.String
		} else {
			dono.AmountSent = "0.0"
		}

		if tmpMediaURL.Valid {
			dono.MediaURL = tmpMediaURL.String
		} else {
			dono.MediaURL = ""
		}

		addToDonosMap(dono)
	}
}

func addToDonosMap(dono utils.Dono) {
	_, ok := donosMap[dono.ID]
	if !ok {
		donosMap[dono.ID] = dono
	}
}

func updateDonoInMap(updatedDono utils.Dono) {
	if _, ok := donosMap[updatedDono.ID]; ok {
		// The dono exists in the map, update it
		donosMap[updatedDono.ID] = updatedDono
	} else {
		// The dono does not exist in the map, handle the error or do nothing
	}
}

func printDonoInfo(dono utils.Dono, secondsElapsedSinceLastCheck, secondsNeededToCheck float64) {
	log.Println("Dono ID:", dono.ID, "Address:", dono.Address, "Name:", dono.Name, "To User:", dono.UserID)
	log.Println("Message:", dono.Message)
	fmt.Println(dono.CurrencyType, "Needed:", dono.AmountToSend, "Recieved:", dono.AmountSent)

	log.Println("Time since check:", fmt.Sprintf("%.2f", secondsElapsedSinceLastCheck), "Needed:", fmt.Sprintf("%.2f", secondsNeededToCheck))

}

func printTransferInfo(t utils.Transfer) {
	fmt.Printf("Block Number: %v\nUnique ID: %v\nHash: %v\nFrom: %v\nTo: %v\nValue: %v\nERC721 Token ID: %v\nERC1155 Metadata: %v\nToken ID: %v\nAsset: %v\nCategory: %v\n",
		t.BlockNum,
		t.UniqueId,
		t.Hash,
		t.From,
		t.To,
		t.Value,
		t.Erc721TokenId,
		t.Erc1155Metadata,
		t.TokenId,
		t.Asset,
		t.Category)
}

func checkUnfulfilledDonos() []utils.Dono {
	ips, _ := getUnfulfilledDonoIPs() // get ips

	updatePendingDonos()

	var fulfilledDonos []utils.Dono

	eth_addresses := returnETHAddresses()
	for _, eth_address := range eth_addresses {
		log.Println("Getting ETH txs for:", eth_address)
	}

	tempMap := make(map[string]bool)
	for _, eth_address := range eth_addresses {
		log.Println("Getting ETH txs for:", eth_address)
		transactions, newTX, _ := utils.GetEth(eth_address)
		if newTX {
			for _, tx := range transactions {
				if _, exists := tempMap[tx.Hash]; !exists {
					eth_transactions = append(eth_transactions, tx)
					tempMap[tx.Hash] = true
				}
			}
			time.Sleep(2 * time.Second)
		}

	}

	for _, dono := range donosMap {
		// Check if the dono has exceeded the killDono time
		if !dono.Fulfilled {
			timeElapsedFromDonoCreation := time.Since(dono.CreatedAt)
			if timeElapsedFromDonoCreation > killDono || dono.Address == " " || dono.AmountToSend == "0.0" {
				dono.Fulfilled = true
				if dono.Address == " " {
					log.Println("No dono address, killed (marked as fulfilled) and won't be checked again. \n")
				} else {
					log.Println("Dono too old, killed (marked as fulfilled) and won't be checked again. \n")
				}
				updateDonoInMap(dono)
				continue
			}
		}

		if dono.CurrencyType != "XMR" && dono.CurrencyType != "SOL" {
			// Check if amount matches a completed dono amount
			for _, transaction := range eth_transactions {
				tN := utils.GetTransactionToken(transaction)
				if tN == dono.CurrencyType {
					valueStr := fmt.Sprintf("%.18f", transaction.Value)
					valueToCheck, _ := utils.StandardizeString(dono.AmountToSend)
					log.Println("TX checked:", tN)
					log.Println("Needed:", valueToCheck)
					log.Println("Got   :", valueStr)
					if valueStr == valueToCheck {
						log.Println("Matching TX!")
						dono.AmountSent = valueStr
						addDonoToDonoBar(dono.AmountSent, dono.CurrencyType, dono.UserID) // change Amount To Send to USD value of sent
						dono.Fulfilled = true
						dono.UpdatedAt = time.Now().UTC()
						fulfilledDonos = append(fulfilledDonos, dono)
						updateDonoInMap(dono)
						break
					}
				}
			}

			valueToCheck, _ := utils.ConvertStringTo18DecimalPlaces(dono.AmountToSend)
			dono.UpdatedAt = time.Now().UTC()
			fmt.Println(valueToCheck, dono.CurrencyType, "Dono incomplete.")
			updateDonoInMap(dono)
			continue
		}

		// Check if the dono needs to be skipped based on exponential backoff
		secondsElapsedSinceLastCheck := time.Since(dono.UpdatedAt).Seconds()
		dono.UpdatedAt = time.Now().UTC()

		expoAdder := returnIPPenalty(ips, dono.EncryptedIP) + time.Since(dono.CreatedAt).Seconds()/60/60/19
		secondsNeededToCheck := math.Pow(float64(baseCheckingRate)-0.02, expoAdder)

		if secondsElapsedSinceLastCheck < secondsNeededToCheck {
			log.Println("Not enough time has passed, skipping. \n")
			continue // If not enough time has passed then ignore
		}

		log.Println("Enough time has passed, checking.")

		if dono.CurrencyType == "XMR" {
			xmrFl, _ := getXMRBalance(dono.Address, dono.UserID)
			xmrSent, _ := utils.StandardizeFloatToString(xmrFl)
			dono.AmountSent = xmrSent
			xmrNeededStr, _ := utils.StandardizeString(dono.AmountToSend)
			printDonoInfo(dono, secondsElapsedSinceLastCheck, secondsNeededToCheck)
			if dono.AmountSent == xmrNeededStr {
				dono.AmountSent, _ = utils.PruneStringByDecimalPoints(dono.AmountToSend, 5)
				addDonoToDonoBar(dono.AmountSent, dono.CurrencyType, dono.UserID)
				dono.Fulfilled = true
				fulfilledDonos = append(fulfilledDonos, dono)
				updateDonoInMap(dono)
				continue
			}
			updateDonoInMap(dono)
		} else if dono.CurrencyType == "SOL" {
			log.Println("SOLANA DONO AMOUNT NEEDED:", dono.AmountToSend)
			if utils.CheckTransactionSolana(dono.AmountToSend, dono.Address, 100) {
				dono.AmountSent, _ = utils.PruneStringByDecimalPoints(dono.AmountToSend, 5)
				addDonoToDonoBar(dono.AmountSent, dono.CurrencyType, dono.UserID) // change Amount To Send to USD value of sent
				dono.Fulfilled = true
				fulfilledDonos = append(fulfilledDonos, dono)
				updateDonoInMap(dono)
				continue
			}
		}
	}
	updateDonosInDB()
	removeFulfilledDonos(fulfilledDonos)
	return fulfilledDonos
}

func removeFulfilledDonos(donos []utils.Dono) {
	for _, dono := range donos {
		if _, ok := donosMap[dono.ID]; ok {
			delete(donosMap, dono.ID)
		}
	}
}

func returnETHAddresses() []string {
	// Use a map to keep track of which addresses have already been added
	addressMap := make(map[string]bool)
	addresses := []string{}

	for _, dono := range donosMap {
		if dono.CurrencyType != "XMR" && dono.CurrencyType != "SOL" {
			// Check if the address has already been added, and if not, add it to the slice and map
			if _, ok := addressMap[dono.Address]; !ok {
				addressMap[dono.Address] = true
				addresses = append(addresses, dono.Address)
			}
		}
	}

	return addresses
}

func updateDonosInDB() {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Loop through the donosMap and update the database with any changes
	for _, dono := range donosMap {
		if dono.Fulfilled && dono.AmountSent != "0.0" {
			log.Println("DONO COMPLETED: ", dono.AmountSent, dono.CurrencyType)
		}
		_, err = db.Exec("UPDATE donos SET user_id=?, dono_address=?, dono_name=?, dono_message=?, amount_to_send=?, amount_sent=?, currency_type=?, anon_dono=?, fulfilled=?, encrypted_ip=?, created_at=?, updated_at=?, usd_amount=?, media_url=? WHERE dono_id=?", dono.UserID, dono.Address, dono.Name, dono.Message, dono.AmountToSend, dono.AmountSent, dono.CurrencyType, dono.AnonDono, dono.Fulfilled, dono.EncryptedIP, dono.CreatedAt, dono.UpdatedAt, dono.USDAmount, dono.MediaURL, dono.ID)
		if err != nil {
			log.Printf("Error updating Dono with ID %d in the database: %v\n", dono.ID, err)
		} else {
			delete(donosMap, dono.ID)
		}
	}
}

func getXMRBalance(checkID string, userID int) (float64, error) {

	portID := getPortID(xmrWallets, userID)

	found := true
	if portID == -100 {
		found = false
	}

	if found {
		fmt.Println("Port ID for user", userID, "is", portID)
	} else {
		fmt.Println("Port ID not found for user", userID)
	}

	url := "http://localhost:" + strconv.Itoa(portID) + "/json_rpc"

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
		return 0.0, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return 0.0, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0.0, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0.0, err
	}

	fmt.Println(result)

	resultMap, ok := result["result"].(map[string]interface{})
	if !ok {
		return 0.0, fmt.Errorf("result key not found in response")
	}

	payments, ok := resultMap["payments"].([]interface{})
	if !ok {
		return 0.0, fmt.Errorf("payments key not found in result map")
	}

	if len(payments) == 0 {
		return 0.0, fmt.Errorf("no payments found for payment ID %s", checkID)
	}

	amount := payments[0].(map[string]interface{})["amount"].(float64)

	return amount / math.Pow(10, 12), nil
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

		err = addColumnIfNotExist(db, table, "dono_gif", "TEXT")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, table, "default_crypto", "TEXT")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, table, "dono_sound", "TEXT")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, table, "alert_url", "TEXT")
		if err != nil {
			return err
		}

		err = removeColumnIfExist(db, table, "progressbar_url")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, "users", "date_enabled", "DATETIME")
		if err != nil {
			return err
		}

		err = addColumnIfNotExist(db, "users", "wallet_uploaded", "BOOLEAN")
		if err != nil {
			return err
		}
	}

	tables = []string{"queue"}
	for _, table := range tables {
		err := addColumnIfNotExist(db, table, "user_id", "TEXT")
		if err != nil {
			return err
		}
	}

	err := updateColumnAlertURLIfNull(db, "users", "alert_url")
	if err != nil {
		return err
	}

	err = updateColumnWalletUploadedIfNull(db, "users", "wallet_uploaded")
	if err != nil {
		return err
	}

	err = updateColumnDateEnabledIfNull(db, "users", "date_enabled")
	if err != nil {
		return err
	}

	return nil
}

func updateColumnWalletUploadedIfNull(db *sql.DB, tableName, columnName string) error {
	if checkDatabaseColumnExist(db, tableName, columnName) {
		_, err := db.Exec(`UPDATE `+tableName+` SET `+columnName+` = ? WHERE `+columnName+` IS NULL`, "0")
		if err != nil {
			return err
		}
	}
	return nil
}

func updateColumnDateEnabledIfNull(db *sql.DB, tableName, columnName string) error {
	if checkDatabaseColumnExist(db, tableName, columnName) {
		_, err := db.Exec(`UPDATE `+tableName+` SET `+columnName+` = ? WHERE `+columnName+` IS NULL`, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	return nil
}

func updateColumnAlertURLIfNull(db *sql.DB, tableName, columnName string) error {
	if checkDatabaseColumnExist(db, tableName, columnName) {
		value := utils.GenerateUniqueURL()
		_, err := db.Exec(`UPDATE `+tableName+` SET `+columnName+` = ? WHERE `+columnName+` IS NULL`, value)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeColumnIfExist(db *sql.DB, tableName, columnName string) error {
	if checkDatabaseColumnExist(db, tableName, columnName) {
		_, err := db.Exec(`ALTER TABLE ` + tableName + ` DROP COLUMN ` + columnName)
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
            amount_to_send TEXT,            
            amount_sent TEXT,
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
        CREATE TABLE IF NOT EXISTS billing (
        	billing_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            amount_this_month FLOAT,
            amount_total FLOAT,
            enabled BOOL,
            need_to_pay BOOL,
            eth_amount TEXT,
            xmr_amount TEXT,
            xmr_pay_id TEXT,
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
            value TEXT NOT NULL,
            active BOOL NOT NULL
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
            modified_at DATETIME,
            links TEXT,
            dono_gif TEXT,
            dono_sound TEXT,
            alert_url TEXT,
            date_enabled DATETIME,
            wallet_uploaded BOOL,
            cryptos_enabled TEXT

        )
    `)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS pendingusers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            HashedPassword BLOB,
            XMRPayID TEXT,
            XMRNeeded TEXT,
            ETHNeeded TEXT
        )
    `)

	if err != nil {
		return err
	}

	err = createObsTable(db)
	if err != nil {
		log.Fatal(err)
	}

	createAdminUser()
	createNewUser("paul", "hunter")

	return nil
}

func createNewInviteCode(value string, active bool) error {
	inviteData := `
        INSERT INTO invites (
            value,
            active
        ) VALUES (?, ?);`
	_, err := db.Exec(inviteData, value, active)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func createNewOBS(db *sql.DB, userID int, message string, needed, sent float64, refresh int, gifFile, soundFile, ttsVoice string) {
	pbData := utils.ProgressbarData{
		Message: message,
		Needed:  needed,
		Sent:    sent,
		Refresh: refresh,
	}
	err := insertObsData(db, userID, gifFile, soundFile, ttsVoice, pbData)
	if err != nil {
		log.Fatal(err)
	}

}

func createAdminUser() {

	createNewUser("admin", "hunter123")
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

func insertObsData(db *sql.DB, userId int, gifName, mp3Name, ttsVoice string, pbData utils.ProgressbarData) error {
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

func updateObsData(db *sql.DB, userID int, gifName string, mp3Name string, ttsVoice string, pbData utils.ProgressbarData) error {

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
	_, err := db.Exec(updateObsData, userID, gifName, mp3Name, ttsVoice, pbData.Message, pbData.Needed, pbData.Sent, userID)
	return err
}

func getObsData(db *sql.DB, userId int) utils.OBSDataStruct {
	var tempObsData utils.OBSDataStruct
	err := db.QueryRow("SELECT gif_name, mp3_name, `message`, needed, sent FROM obs WHERE user_id = ?", userId).
		Scan(&tempObsData.FilenameGIF, &tempObsData.FilenameMP3, &tempObsData.Message, &tempObsData.Needed, &tempObsData.Sent)
	if err != nil {
		log.Println("Error:", err)
	}

	return tempObsData
}

func createNewUser(username, password string) error {
	log.Println("running createNewUser")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return err
	}
	// create admin user if not exists
	user := getNewUser(username, hashedPassword)
	userID := createUser(user)
	if userID != 0 {
		createNewOBS(db, userID, "default message", 100.00, 50.00, 5, user.DonoGIF, user.DonoSound, "test_voice")
		log.Println("createUser() succeeded, so OBS row was created.")
	} else {
		log.Println("createUser() didn't succeed, so OBS row wasn't created.")
	}

	log.Println("finished createNewUser")
	return nil
}

func createUser(user utils.User) int {
	log.Println("running CreateUser")
	// Insert the user's data into the database

	ce := utils.CryptosEnabled{
		XMR:   false,
		SOL:   true,
		ETH:   true,
		PAINT: true,
		HEX:   true,
		MATIC: true,
		BUSD:  true,
		SHIB:  true,
		PNK:   true,
	}

	ce_ := cryptosStructToJSONString(ce)

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
            links,
            dono_gif,
            dono_sound,
            alert_url,
            date_enabled,
            wallet_uploaded,
            cryptos_enabled,
            default_crypto
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, user.Username, user.HashedPassword, user.EthAddress, user.SolAddress, user.HexcoinAddress, "", user.MinDono, user.MinMediaDono, user.MediaEnabled, time.Now().UTC(), time.Now(), "", user.DonoGIF, user.DonoSound, user.AlertURL, user.DateEnabled, 0, ce_, user.DefaultCrypto)

	if err != nil {
		log.Println(err)
		return 0
	}

	// Get the ID of the newly created user
	row := db.QueryRow(`SELECT last_insert_rowid()`)
	var userID int
	err = row.Scan(&userID)
	if err != nil {
		log.Println(err)
		return 0
	}

	billing := utils.BillingData{
		UserID:          userID,
		AmountThisMonth: 0.00,
		AmountTotal:     0.00,
		Enabled:         true,
		NeedToPay:       false,
		ETHAmount:       "",
		XMRAmount:       "",
		XMRPayID:        "",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	_, err = db.Exec(`
        INSERT INTO billing (
            user_id,
            amount_this_month,
            amount_total,
            enabled,
            need_to_pay,
            eth_amount,
            xmr_amount,
            xmr_pay_id,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, billing.UserID, billing.AmountThisMonth, billing.AmountTotal, billing.Enabled, billing.NeedToPay, "", "", "", billing.CreatedAt, billing.CreatedAt)

	user.BillingData = billing
	globalUsers[userID] = user

	log.Printf("BillingData.Enabled: %v", billing.Enabled)

	// Create a directory for the user based on their ID
	userDir := fmt.Sprintf("users/%d", userID)
	err = os.MkdirAll(userDir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	// Create "gifs" and "sounds" subfolders inside the user's directory
	gifsDir := fmt.Sprintf("%s/gifs", userDir)
	err = os.MkdirAll(gifsDir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	soundsDir := fmt.Sprintf("%s/sounds", userDir)
	err = os.MkdirAll(soundsDir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	moneroDir := fmt.Sprintf("%s/monero", userDir)
	err = os.MkdirAll(moneroDir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	minDonoValue = float64(user.MinDono)
	log.Println("finished createNewUser")

	_, err = getAllUsers()
	if err != nil {
		log.Fatalf("createUser() getAllUsers() error:", err)
	}

	return userID
}

// update an existing code
func updateInviteCode(code utils.InviteCode) error {

	inviteCodeMap[code.Value] = code
	statement := `
		UPDATE invites
		SET value=?, active=?
		WHERE value=?
	`
	_, err := db.Exec(statement, code.Value, code.Active, code.Value)
	if err != nil {
		log.Fatalf("failed, err: %v", err)
	}
	return err
}

// update an existing user
func updateUser(user utils.User) error {
	globalUsers[user.UserID] = user
	statement := `
		UPDATE users
		SET Username=?, HashedPassword=?, eth_address=?, sol_address=?, hex_address=?,
			xmr_wallet_password=?, min_donation_threshold=?, min_media_threshold=?, media_enabled=?, modified_at=?, links=?, dono_gif=?, dono_sound=?, alert_url=?, date_enabled=?, wallet_uploaded=?, cryptos_enabled=?, default_crypto=?
		WHERE id=?
	`
	_, err := db.Exec(statement, user.Username, user.HashedPassword, user.EthAddress,
		user.SolAddress, user.HexcoinAddress, user.XMRWalletPassword, user.MinDono, user.MinMediaDono,
		user.MediaEnabled, time.Now().UTC(), user.Links, user.DonoGIF, user.DonoSound, user.AlertURL, user.DateEnabled, user.WalletUploaded, cryptosStructToJSONString(user.CryptosEnabled), user.DefaultCrypto, user.UserID)
	if err != nil {
		log.Fatalf("failed, err: %v", err)
	}

	statement = `
		UPDATE billing
		SET user_id=?, amount_this_month=?, amount_total=?, enabled=?, need_to_pay=?,
			eth_amount=?, xmr_amount=?, xmr_pay_id=?, created_at=?, updated_at=?
		WHERE billing_id=?
	`
	_, err = db.Exec(statement, user.UserID, user.BillingData.AmountThisMonth, user.BillingData.AmountTotal, user.BillingData.Enabled,
		user.BillingData.NeedToPay, user.BillingData.ETHAmount, user.BillingData.XMRAmount, user.BillingData.XMRPayID, user.BillingData.CreatedAt,
		user.BillingData.UpdatedAt, user.BillingData.UserID)
	if err != nil {
		log.Fatalf("failed, err: %v", err)
	}

	solWallets[user.UserID] = utils.SolWallet{
		Address: user.SolAddress,
		Amount:  0.00,
	}

	utils.SetSolWallets(solWallets)
	return err
}

func getUserByAlertURL(AlertURL string) (utils.User, error) {
	var user utils.User
	var links, donoGIF, defaultCrypto, donoSound, alertURL, cryptosEnabled sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT * FROM users WHERE alert_url=?", AlertURL)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound, &alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)
	if err != nil {
		return utils.User{}, err
	}
	user.Links = links.String
	if !links.Valid {
		user.Links = ""
	}
	user.DonoGIF = donoGIF.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoGIF.Valid {           // check if the "dono_gif" column is null
		user.DonoGIF = "default.gif" // set the user's "DonoGIF"
	}
	user.DonoSound = donoSound.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoSound.Valid {             // check if the "dono_gif" column is null
		user.DonoSound = "default.mp3" // set the user's "DonoSound"
	}

	user.DefaultCrypto = defaultCrypto.String // assign the sql.NullString to the user's "DonoGIF" field
	if !defaultCrypto.Valid {                 // check if the "dono_gif" column is null
		user.DefaultCrypto = "" // set the user's "DonoSound"
	}

	user.AlertURL = alertURL.String // assign the sql.NullString to the user's "DonoGIF" field
	if !alertURL.Valid {            // check if the "dono_gif" column is null
		user.AlertURL = utils.GenerateUniqueURL() // set the user's "DonoSound"
	}

	ce := utils.CryptosEnabled{
		XMR:   true,
		SOL:   true,
		ETH:   false,
		PAINT: false,
		HEX:   true,
		MATIC: false,
		BUSD:  true,
		SHIB:  false,
		PNK:   true,
	}

	user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String) // assign the sql.NullString to the user's "DonoGIF" field
	if !cryptosEnabled.Valid {                                             // check if the "dono_gif" column is null
		user.CryptosEnabled = ce // set the user's "DonoSound"
	}

	return user, nil
}

func getOBSDataByAlertURL(AlertURL string) (utils.OBSDataStruct, error) {
	user, err := getUserByAlertURL(AlertURL)
	if err != nil {
		log.Println("Couldn't get user,", err)
	}
	var obsData utils.OBSDataStruct
	//var alertURL sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT gif_name, mp3_name, `message`, needed, sent FROM obs WHERE user_id=?", user.UserID)

	err = row.Scan(&obsData.FilenameGIF, &obsData.FilenameMP3, &obsData.Message, &obsData.Needed, &obsData.Sent)
	if err != nil {
		log.Println("Couldn't get obsData,", err)
		return obsData, err
	}

	return obsData, nil

}

func getOBSDataByUserID(userID int) (utils.OBSDataStruct, error) {
	var obsData utils.OBSDataStruct
	//var alertURL sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT gif_name, mp3_name, `message`, needed, sent FROM obs WHERE user_id=?", userID)

	err := row.Scan(&obsData.FilenameGIF, &obsData.FilenameMP3, &obsData.Message, &obsData.Needed, &obsData.Sent)
	if err != nil {
		log.Println("Couldn't get obsData,", err)
		return obsData, err
	}

	return obsData, nil

}

// get a user by their session token
func getUserBySessionCached(sessionToken string) (utils.User, bool) {
	userID, ok := userSessions[sessionToken]
	if !ok {
		log.Println("session token not found")
		return globalUsers[0], false
	}
	for _, user := range globalUsers {
		if user.UserID == userID {
			return user, true
		}
	}
	return globalUsers[0], false
}

func getUserByUsernameCached(username string) (utils.User, bool) {
	for _, user := range globalUsers {
		if user.Username == username {
			return user, true
		}
	}
	return globalUsers[0], false

}

// get a user by their username
func getUserByUsername(username string) (utils.User, error) {
	var user utils.User
	var links, donoGIF, defaultCrypto, donoSound, alertURL, cryptosEnabled sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT * FROM users WHERE Username=?", username)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound, &alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)
	if err != nil {
		return utils.User{}, err
	}
	user.Links = links.String
	if !links.Valid {
		user.Links = ""
	}
	user.DonoGIF = donoGIF.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoGIF.Valid {           // check if the "dono_gif" column is null
		user.DonoGIF = "default.gif" // set the user's "DonoGIF"
	}
	user.DonoSound = donoSound.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoSound.Valid {             // check if the "dono_gif" column is null
		user.DonoSound = "default.mp3" // set the user's "DonoSound"
	}

	user.DefaultCrypto = defaultCrypto.String // assign the sql.NullString to the user's "DonoGIF" field
	if !defaultCrypto.Valid {                 // check if the "dono_gif" column is null
		user.DefaultCrypto = "" // set the user's "DonoSound"
	}

	user.AlertURL = alertURL.String // assign the sql.NullString to the user's "DonoGIF" field
	if !alertURL.Valid {            // check if the "dono_gif" column is null
		user.AlertURL = utils.GenerateUniqueURL() // set the user's "DonoSound"
	}

	ce := utils.CryptosEnabled{
		XMR:   true,
		SOL:   true,
		ETH:   false,
		PAINT: false,
		HEX:   true,
		MATIC: false,
		BUSD:  true,
		SHIB:  false,
		PNK:   true,
	}

	user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String) // assign the sql.NullString to the user's "DonoGIF" field
	if !cryptosEnabled.Valid {                                             // check if the "dono_gif" column is null
		user.CryptosEnabled = ce // set the user's "DonoSound"
	}

	user = setUserMinDonos(user)

	return user, nil

}

// check a user by their ID
func checkUserByID(id int) bool {
	var user utils.User
	var links, donoGIF, donoSound, defaultCrypto, alertURL, cryptosEnabled sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT * FROM users WHERE id=?", id)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound, &alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)

	ce := utils.CryptosEnabled{
		XMR:   true,
		SOL:   true,
		ETH:   false,
		PAINT: false,
		HEX:   true,
		MATIC: false,
		BUSD:  true,
		SHIB:  false,
		PNK:   true,
	}

	user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String) // assign the sql.NullString to the user's "DonoGIF" field
	if !cryptosEnabled.Valid {                                             // check if the "dono_gif" column is null
		user.CryptosEnabled = ce // set the user's "DonoSound"
	}

	user.DefaultCrypto = defaultCrypto.String // assign the sql.NullString to the user's "DonoGIF" field
	if !defaultCrypto.Valid {                 // check if the "dono_gif" column is null
		user.DefaultCrypto = "" // set the user's "DonoSound"
	}

	if err == sql.ErrNoRows {
		log.Println("checkUserByID(", id, "): User doesn't exist")
		return false // user doesn't exist
	} else if err != nil {
		log.Println("checkUserByID(", id, ") Error:", err)
		return false
	}
	return true // user exists

}

func printUserColumns() error {
	rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'users';`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var column string
	for rows.Next() {
		err = rows.Scan(&column)
		if err != nil {
			return err
		}
		fmt.Println(column)
	}
	return rows.Err()
}

// check a user by their username and return a bool and the id
func checkUserByUsername(username string) (bool, int) {
	printUserColumns()
	var user utils.User
	var links, donoGIF, donoSound, defaultCrypto, alertURL, cryptosEnabled sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT * FROM users WHERE Username=?", username)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound, &alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)

	ce := utils.CryptosEnabled{
		XMR:   true,
		SOL:   true,
		ETH:   false,
		PAINT: false,
		HEX:   true,
		MATIC: false,
		BUSD:  true,
		SHIB:  false,
		PNK:   true,
	}

	user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String) // assign the sql.NullString to the user's "DonoGIF" field
	if !cryptosEnabled.Valid {                                             // check if the "dono_gif" column is null
		user.CryptosEnabled = ce // set the user's "DonoSound"
	}

	user.DefaultCrypto = defaultCrypto.String // assign the sql.NullString to the user's "DonoGIF" field
	if !defaultCrypto.Valid {                 // check if the "dono_gif" column is null
		user.DefaultCrypto = "" // set the user's "DonoSound"
	}

	if err == sql.ErrNoRows {
		log.Println("checkUserByUsername(", username, "): User doesn't exist")
		return false, 0 // user doesn't exist
	} else if err != nil {
		log.Println("checkUserByUsername(", username, ") Error:", err)
		return false, 0
	}
	return true, user.UserID // user exists, return true and the user's ID
}

// get a user by their session token
func getUserBySession(sessionToken string) (utils.User, error) {
	userID, ok := userSessions[sessionToken]
	if !ok {
		return utils.User{}, fmt.Errorf("session token not found")
	}
	var user utils.User
	var links, donoGIF, defaultCrypto, donoSound, alertURL, cryptosEnabled sql.NullString // use sql.NullString for the "links" and "dono_gif" fields
	row := db.QueryRow("SELECT * FROM users WHERE id=?", userID)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime, &links, &donoGIF, &donoSound, &alertURL, &user.DateEnabled, &user.WalletUploaded, &cryptosEnabled, &defaultCrypto)
	if err != nil {
		return utils.User{}, err
	}
	user.Links = links.String
	if !links.Valid {
		user.Links = ""
	}
	user.DonoGIF = donoGIF.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoGIF.Valid {           // check if the "dono_gif" column is null
		user.DonoGIF = "default.gif" // set the user's "DonoGIF"
	}
	user.DonoSound = donoSound.String // assign the sql.NullString to the user's "DonoGIF" field
	if !donoSound.Valid {             // check if the "dono_gif" column is null
		user.DonoSound = "default.mp3" // set the user's "DonoSound"
	}
	user.DefaultCrypto = defaultCrypto.String // assign the sql.NullString to the user's "DonoGIF" field
	if !defaultCrypto.Valid {                 // check if the "dono_gif" column is null
		user.DefaultCrypto = "" // set the user's "DonoSound"
	}

	user.AlertURL = alertURL.String // assign the sql.NullString to the user's "DonoGIF" field
	if !alertURL.Valid {            // check if the "dono_gif" column is null
		user.AlertURL = utils.GenerateUniqueURL() // set the user's "DonoSound"
	}

	ce := utils.CryptosEnabled{
		XMR:   true,
		SOL:   true,
		ETH:   false,
		PAINT: false,
		HEX:   true,
		MATIC: false,
		BUSD:  true,
		SHIB:  false,
		PNK:   true,
	}

	user.CryptosEnabled = cryptosJsonStringToStruct(cryptosEnabled.String) // assign the sql.NullString to the user's "DonoGIF" field
	if !cryptosEnabled.Valid {                                             // check if the "dono_gif" column is null
		user.CryptosEnabled = ce // set the user's "DonoSound"
	}

	return user, nil
}

// verify that the entered password matches the stored hashed password for a user
func verifyPassword(user utils.User, password string) bool {
	err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		username = strings.ToLower(username)
		password := r.FormValue("password")

		user, valid := getUserByUsernameCached(username)

		if !valid {
			log.Println("Can't find username")
			http.Redirect(w, r, "/incorrect_login", http.StatusFound)
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
	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	obsData.URLdonobar = host_url + "progressbar?value=" + user.AlertURL
	obsData.URLdisplay = host_url + "alert?value=" + user.AlertURL
	obsData_ := getObsData(db, user.UserID)
	obsData_.Username = user.Username

	if r.Method == http.MethodPost {
		r.ParseMultipartForm(5 << 10) // max file size of 10 MB
		userDir := fmt.Sprintf("users/%d/", user.UserID)

		// Get the files from the request
		fileGIF, handlerGIF, err := r.FormFile("dono_animation")
		if err == nil {
			defer fileGIF.Close()
			fileNameGIF := handlerGIF.Filename
			fileBytesGIF, err := ioutil.ReadAll(fileGIF)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err = os.WriteFile(userDir+"/gifs/default.gif", fileBytesGIF, 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			obsData_.FilenameGIF = fileNameGIF
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
			if err = os.WriteFile(userDir+"/sounds/default.mp3", fileBytesMP3, 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			obsData_.FilenameMP3 = fileNameMP3
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

		obsData_.Message = pbMessage
		obsData_.Needed = amountNeeded
		obsData_.Sent = amountSent

		pb.Message = pbMessage
		pb.Needed = amountNeeded
		pb.Sent = amountSent

		err = updateObsData(db, user.UserID, obsData_.FilenameGIF, obsData_.FilenameMP3, "alice", pb)

		if err != nil {
			log.Println("Error: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {

	}

	log.Println(obsData_.Message)
	log.Println(obsData_.Needed)
	log.Println(obsData_.Sent)
	obsData_.URLdonobar = host_url + "progressbar?value=" + user.AlertURL
	obsData_.URLdisplay = host_url + "alert?value=" + user.AlertURL
	log.Println(obsData.URLdonobar)
	log.Println(obsData.URLdisplay)

	tmpl, err := template.ParseFiles("web/obs/settings.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, obsData_)

}

// handle requests to modify user data
func userHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		user.EthAddress = r.FormValue("ethaddress")
		user.SolAddress = r.FormValue("soladdress")
		user.HexcoinAddress = r.FormValue("hexcoinaddress")
		user.XMRWalletPassword = r.FormValue("xmrwalletpassword")
		user.MinDono, _ = strconv.Atoi(r.FormValue("mindono"))
		user.MinMediaDono, _ = strconv.Atoi(r.FormValue("minmediadono"))
		mediaEnabled := r.FormValue("mediaenabled") == "on"
		user.MediaEnabled = mediaEnabled

		user = setUserMinDonos(user)
		err := updateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}

	if user.Links == "" {
		user.Links = "[]"
	}

	data := struct {
		User  utils.User
		Links string // Changed to string to hold JSON
	}{
		User:  user,
		Links: user.Links, // Convert byte slice to string
	}

	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, data)

}

func updateLinksHandler(w http.ResponseWriter, r *http.Request) {
	// Get the links parameter from the POST request
	linksJson := r.PostFormValue("links")
	username := r.PostFormValue("username")

	cookie, _ := r.Cookie("session_token")
	user, _ := getUserBySessionCached(cookie.Value)

	if user.Username == username {

		// Parse the JSON string into a slice of Link structs
		var links []utils.Link
		err := json.Unmarshal([]byte(linksJson), &links)
		if err != nil {
			// Handle error
			return
		}

		user.Links = linksJson
		updateUser(user)
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/user", http.StatusSeeOther)
	return
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// retrieve user from session
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user, valid := getUserBySessionCached(sessionToken.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// initialize user page data struct
	data := utils.UserPageData{}

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

func changeUserMoneroHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting change user handler function")
	// retrieve user from session
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user, valid := getUserBySessionCached(sessionToken.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// initialize user page data struct
	data := utils.UserPageData{}

	// process form submission
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if user.WalletUploaded {
			stopMoneroWallet(user)
		}

		// Get the uploaded monero wallet file and save it to disk
		moneroDir := fmt.Sprintf("users/%d/monero", user.UserID)
		file, header, err := r.FormFile("moneroWallet")
		walletUploadServer := false
		walletKeysUploadServer := false
		if err == nil {
			defer file.Close()
			walletPath := filepath.Join(moneroDir, "wallet")
			err = saveFileToDisk(file, header, walletPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				user.WalletUploaded = false
				return
			} else {
				walletUploadServer = true
			}

		}

		// Get the uploaded monero wallet keys file and save it to disk
		file, header, err = r.FormFile("moneroWalletKeys")
		if err == nil {
			defer file.Close()
			walletKeyPath := filepath.Join(moneroDir, "wallet.keys")
			err = saveFileToDisk(file, header, walletKeyPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				user.WalletUploaded = false
				return
			} else {
				walletKeysUploadServer = true
			}
		}

		if walletUploadServer && walletKeysUploadServer {

			// convert xmrWallets to a map
			existingWallets := make(map[int]int)
			for _, wallet := range xmrWallets {
				existingWallets[wallet[0]*10000+wallet[1]] = 1
			}

			user.WalletUploaded = true
			walletRunning := true
			log.Println("Monero wallet uploaded")
			// check if the element exists in the map and append if not
			if _, ok := existingWallets[user.UserID*10000+starting_port]; !ok {
				xmrWallets = append(xmrWallets, []int{user.UserID, starting_port})
				walletRunning = false
			}
			go startMoneroWallet(starting_port, user.UserID, user)
			if !walletRunning {
				starting_port++
			}
		}

		// Update the user with the new data
		err = updateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to the user page
		http.Redirect(w, r, "/user", http.StatusSeeOther)
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

func registerUserHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		user, valid := getUserBySessionCached(cookie.Value)
		if valid && !checkLoggedInAdmin(w, r) {
			log.Println("Already logged in as", user.Username, " - redirecting from registration to user panel.")
			http.Redirect(w, r, "/user", http.StatusSeeOther)
			return
		}
	}

	err = registerTemplate.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func changeUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting change user handler function")
	// retrieve user from session
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user, valid := getUserBySessionCached(sessionToken.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// initialize user page data struct
	data := utils.UserPageData{}

	// process form submission
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user.EthAddress = r.FormValue("ethereumAddress")
		user.SolAddress = r.FormValue("solanaAddress")
		user.HexcoinAddress = r.FormValue("hexcoinAddress")
		minDono, _ := strconv.Atoi(r.FormValue("minUsdAmount"))
		user.MinDono = minDono
		minDonoValue = float64(minDono)

		// Update the user with the new data

		user = setUserMinDonos(user)
		err = updateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to the user page
		http.Redirect(w, r, "/user", http.StatusSeeOther)
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

func saveFileToDisk(file multipart.File, header *multipart.FileHeader, path string) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		return err
	}

	return nil
}

func renderChangePasswordForm(w http.ResponseWriter, data utils.UserPageData) {
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

func getUserPathByID(id int) string {
	return fmt.Sprintf("users/%d/", id)
}

func checkFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err == nil {
		// File exists
		return true
	} else {
		return false
	}

}

func checkUserGIF(userpath string) bool {
	up := userpath + "gifs/default.gif"
	//log.Println("checking", up)
	b := checkFileExists(up)
	if b {
		log.Println("user gif exists")
	} else {
		log.Println("user gif doesn't exist")
	}
	return b
}

func checkUserSound(userpath string) bool {
	up := userpath + "sounds/default.mp3"
	//log.Println("checking", up)
	b := checkFileExists(up)
	if b {
		log.Println("user sound exists")
	} else {
		log.Println("user sound doesn't exist")
	}
	return b
}

func checkUserMoneroWallet(userpath string) bool {
	up := userpath + "monero/wallet"
	//log.Println("checking", up)
	b := checkFileExists(up)
	if b {
		log.Println("user wallet exists")
	} else {
		log.Println("user wallet doesn't exist")
	}
	return b
}

func checkUserMoneroWalletKeys(userpath string) bool {
	up := userpath + "monero/wallet"
	//log.Println("checking", up)
	b := checkFileExists(up)
	if b {
		log.Println("user wallet keys exists")
	} else {
		log.Println("user wallet keys doesn't exist")
	}
	return b
}

func alertOBSHandler(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	user, _ := getUserByAlertURL(value)

	newDono, err := checkDonoQueue(db, user.UserID)
	a.Userpath = getUserPathByID(user.UserID)

	if !checkUserGIF(a.Userpath) || !checkUserSound(a.Userpath) { // check if user has uploaded custom gif/sounds for alert
		a.Userpath = "media/"
	}

	if err != nil {
		log.Printf("Error checking donation queue: %v\n", err)
	}

	if newDono {
		fmt.Println("Showing NEW DONO!")
		a.DisplayToggle = ""
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
	value := r.URL.Query().Get("value")
	obsData, err := getOBSDataByAlertURL(value)

	if err != nil {
		log.Println(err)
		err_ := indexTemplate.Execute(w, nil)
		return
		if err_ != nil {
			http.Error(w, err_.Error(), http.StatusInternalServerError)
			return
		}
	}

	/*log.Println("Progress bar message:", obsData.Message)
	log.Println("Progress bar needed:", obsData.Needed)
	log.Println("Progress bar sent:", obsData.Sent)*/

	pb.Message = obsData.Message
	pb.Needed = obsData.Needed
	pb.Sent = obsData.Sent

	err = progressbarTemplate.Execute(w, pb)
	if err != nil {
		fmt.Println(err)
	}
}

func cryptosStructToJSONString(s utils.CryptosEnabled) string {
	bytes, err := json.Marshal(s)
	if err != nil {
		log.Println("cryptosStructToJSONString error:", err)
		return ""
	}
	return string(bytes)
}

func cryptosJsonStringToStruct(jsonStr string) utils.CryptosEnabled {
	var s utils.CryptosEnabled
	err := json.Unmarshal([]byte(jsonStr), &s)
	if err != nil {
		log.Println("cryptosJsonStringToStruct error:", err)
		return utils.CryptosEnabled{}
	}
	return s
}

func cryptoSettingsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		fmt.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user, valid := getUserBySessionCached(cookie.Value)
	if !valid || r.Method == http.MethodPost {
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	} else {
		userPath := getUserPathByID(user.UserID)
		moneroWalletString := "monero wallet not uploaded"
		moneroWalletKeysString := "monero wallet not key uploaded"

		if checkUserMoneroWallet(userPath) && !CheckMoneroPort(user.UserID) {
			moneroWalletString = "monero wallet uploaded but not running correctly. Please ensure you have created a view only wallet with no password."
			moneroWalletKeysString = "monero wallet key uploaded but not running correctly. Please ensure you have created a view only wallet with no password."
		}

		data := struct {
			UserID                 int
			Username               string
			HashedPassword         []byte
			EthAddress             string
			SolAddress             string
			HexcoinAddress         string
			XMRWalletPassword      string
			MinDono                int
			MinMediaDono           int
			MediaEnabled           bool
			CreationDatetime       string
			ModificationDatetime   string
			Links                  string
			DonoGIF                string
			DonoSound              string
			AlertURL               string
			MinSol                 float64
			MinEth                 float64
			MinXmr                 float64
			MinPaint               float64
			MinHex                 float64
			MinMatic               float64
			MinBusd                float64
			MinShib                float64
			MinUsdc                float64
			MinTusd                float64
			MinWbtc                float64
			MinPnk                 float64
			DateEnabled            time.Time
			WalletUploaded         bool
			WalletPending          bool
			CryptosEnabled         utils.CryptosEnabled
			BillingData            utils.BillingData
			MoneroWalletString     string
			MoneroWalletKeysString string
		}{
			UserID:                 user.UserID,
			Username:               user.Username,
			HashedPassword:         user.HashedPassword,
			EthAddress:             user.EthAddress,
			SolAddress:             user.SolAddress,
			HexcoinAddress:         user.HexcoinAddress,
			XMRWalletPassword:      user.XMRWalletPassword,
			MinDono:                user.MinDono,
			MinMediaDono:           user.MinMediaDono,
			MediaEnabled:           user.MediaEnabled,
			CreationDatetime:       user.CreationDatetime,
			ModificationDatetime:   user.ModificationDatetime,
			Links:                  user.Links,
			DonoGIF:                user.DonoGIF,
			DonoSound:              user.DonoSound,
			AlertURL:               user.AlertURL,
			MinSol:                 user.MinSol,
			MinEth:                 user.MinEth,
			MinXmr:                 user.MinXmr,
			MinPaint:               user.MinPaint,
			MinHex:                 user.MinHex,
			MinMatic:               user.MinMatic,
			MinBusd:                user.MinBusd,
			MinShib:                user.MinShib,
			MinUsdc:                user.MinUsdc,
			MinTusd:                user.MinTusd,
			MinWbtc:                user.MinWbtc,
			MinPnk:                 user.MinPnk,
			DateEnabled:            user.DateEnabled,
			WalletUploaded:         user.WalletUploaded,
			WalletPending:          user.WalletPending,
			CryptosEnabled:         user.CryptosEnabled,
			BillingData:            user.BillingData,
			MoneroWalletString:     moneroWalletString,
			MoneroWalletKeysString: moneroWalletKeysString,
		}

		tmpl, err := template.ParseFiles("web/cryptoselect.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, header, subheader, message string) {
	if r.Method == http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else {
		data := struct {
			ErrorHeader    string
			ErrorSubHeader string
			ErrorMessage   string
		}{
			ErrorHeader:    header,
			ErrorSubHeader: subheader,
			ErrorMessage:   message,
		}

		tmpl, err := template.ParseFiles("web/err.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func tosHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore requests for the favicon
	if r.URL.Path == "/favicon.ico" {
		return
	}

	err := tosTemplate.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func overflowHandler(w http.ResponseWriter, r *http.Request) {
	err := overflowTemplate.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}

	if ip == "" {
		ip = r.RemoteAddr
	}

	return ip
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	// Ignore requests for the favicon
	if r.URL.Path == "/favicon.ico" {
		return
	}
	// Get the username from the URL path
	username := r.URL.Path[1:]

	username = strings.ToLower(username)
	user_, valid := getUserByUsernameCached(username)
	// Calculate all minimum donations
	user := globalUsers[user_.UserID]
	log.Println("user ID in indexHandler =", user.UserID)
	if valid && username != "admin" {
		if user.Links == "" {
			user.Links = "[]"
		}

		if user.DefaultCrypto == "" {
			if user.CryptosEnabled.XMR {
				user.DefaultCrypto = "XMR"
			} else if user.CryptosEnabled.SOL {
				user.DefaultCrypto = "SOL"
			} else if user.CryptosEnabled.ETH {
				user.DefaultCrypto = "ETH"
			} else if user.CryptosEnabled.PAINT {
				user.DefaultCrypto = "PAINT"
			} else if user.CryptosEnabled.HEX {
				user.DefaultCrypto = "HEX"
			} else if user.CryptosEnabled.MATIC {
				user.DefaultCrypto = "MATIC"
			} else if user.CryptosEnabled.BUSD {
				user.DefaultCrypto = "BUSD"
			} else if user.CryptosEnabled.SHIB {
				user.DefaultCrypto = "SHIB"
			} else if user.CryptosEnabled.PNK {
				user.DefaultCrypto = "PNK"
			}

		}

		i := utils.IndexDisplay{
			MaxChar:        MessageMaxChar,
			MinDono:        user.MinDono,
			MinSolana:      user.MinSol,
			MinEthereum:    user.MinEth,
			MinMonero:      user.MinXmr,
			MinHex:         user.MinHex,
			MinPolygon:     user.MinMatic,
			MinBusd:        user.MinBusd,
			MinShib:        user.MinShib,
			MinPnk:         user.MinPnk,
			MinPaint:       user.MinPaint,
			SolPrice:       prices.Solana,
			ETHPrice:       prices.Ethereum,
			XMRPrice:       prices.Monero,
			PolygonPrice:   prices.Polygon,
			HexPrice:       prices.Hexcoin,
			BusdPrice:      prices.BinanceUSD,
			ShibPrice:      prices.ShibaInu,
			PnkPrice:       prices.Kleros,
			PaintPrice:     prices.Paint,
			CryptosEnabled: user.CryptosEnabled,
			Checked:        checked,
			Links:          user.Links,
			WalletPending:  user.WalletPending,
			DefaultCrypto:  user.DefaultCrypto,
			Username:       username,
		}

		err := donationTemplate.Execute(w, i)
		if err != nil {
			fmt.Println(err)
		}
	} else {

		errorHandler(w, r, "User not found", "didn't find a ferret account with that username", "No username was found.")

		// If no username is present in the URL path, serve the indexTemplate
		err := indexTemplate.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func checkDonoQueue(db *sql.DB, userID int) (bool, error) {

	// Fetch oldest entry from queue table where user_id matches userID
	row := db.QueryRow("SELECT name, message, amount, currency, media_url, usd_amount FROM queue WHERE user_id = ? ORDER BY rowid LIMIT 1", userID)

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
	a.Amount, _ = strconv.ParseFloat(utils.PruneStringDecimals(fmt.Sprintf("%f", amount), 4), 64)
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

func checkValidInviteCode(ic string) bool {
	if _, ok := inviteCodeMap[ic]; ok {
		if inviteCodeMap[ic].Active {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

func newAccountHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	invitecode := r.FormValue("invitecode")

	username = utils.SanitizeStringLetters(username)

	password := r.FormValue("password")
	isAdmin := checkLoggedInAdmin(w, r)
	_, validUser := getUserByUsernameCached(username)
	if r.Method != http.MethodPost || (validUser && !isAdmin) {
		// Redirect to the payment page if the request is not a POST request
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !PublicRegistrationsEnabled {
		if isAdmin || checkValidInviteCode(invitecode) {
			if !checkUsernamePendingOrCreated(username) {
				err_ := createNewUser(username, password)
				if err_ != nil {
					log.Println(err_)
				} else {
					inviteCodeMap[invitecode] = utils.InviteCode{Value: invitecode, Active: false}
					updateInviteCode(inviteCodeMap[invitecode])
				}
				http.Redirect(w, r, "/user", http.StatusSeeOther)
				return
			} else {
				errorHandler(w, r, "Username invalid.", "Woops, the username you tried seems to be already registered.", "Your invite code worked, but the username you chose does not. Please go back and try to register a different username.")
				return
			}
		} else {
			errorHandler(w, r, "Incorrect invite code", "Woops, the invite code you tried to use is invalid.", "Your invite code is not valid. Please go back and try again, making sure your invite code is inputted correctly.")
			return
		}
	} else {
		if !checkUsernamePendingOrCreated(username) {
			pendingUser, err := createNewPendingUser(username, password)
			if err != nil {
				log.Println(err)
			}

			xmrNeeded, err := strconv.ParseFloat(pendingUser.XMRNeeded, 64)
			if err != nil {
				// Handle the error
			}

			xmrNeededFormatted := fmt.Sprintf("%.5f", xmrNeeded)

			d := utils.AccountPayData{
				Username:    pendingUser.Username,
				AmountXMR:   xmrNeededFormatted,
				AmountETH:   pendingUser.ETHNeeded,
				AddressXMR:  pendingUser.XMRAddress,
				AddressETH:  pendingUser.ETHAddress,
				UserID:      pendingUser.ID,
				DateCreated: time.Now().UTC(),
			}

			tmp, _ := qrcode.Encode(fmt.Sprintf("monero:%s?tx_amount=%s", pendingUser.XMRAddress, pendingUser.XMRNeeded), qrcode.Low, 320)
			d.QRB64XMR = base64.StdEncoding.EncodeToString(tmp)

			donationLink := fmt.Sprintf("ethereum:%s?value=%s", pendingUser.ETHAddress, pendingUser.ETHNeeded)
			tmp, _ = qrcode.Encode(donationLink, qrcode.Low, 320)
			d.QRB64ETH = base64.StdEncoding.EncodeToString(tmp)

			err = accountPayTemplate.Execute(w, d)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			errorHandler(w, r, "Username invalid.", "Woops, the username you tried seems to be already registered.", "The username you chose is already taken or invalid. Please go back and try to register a different username.")
			return
		}
	}
}

func checkUsernamePendingOrCreated(username_ string) bool {
	username := strings.ToLower(username_)
	for _, route_ := range routes_ {
		if utils.SanitizeStringLetters(route_.Path) == username {
			return true
		}
	}

	for _, user := range pendingGlobalUsers {
		if user.Username == username {
			return true
		}

	}

	for _, user := range globalUsers {
		if user.Username == username {
			return true
		}

	}

	return false

}

func accountBillingHandler(w http.ResponseWriter, r *http.Request) {
	checkLoggedIn(w, r)
	cookie, _ := r.Cookie("session_token")
	user, _ := getUserBySessionCached(cookie.Value)

	if user.BillingData.NeedToPay {

		admin, _ := getUserByUsernameCached("admin")

		xmrNeededFormatted := fmt.Sprintf("%.5f", user.BillingData.XMRAmount)
		d := utils.AccountPayData{
			Username:    user.Username,
			AmountXMR:   xmrNeededFormatted,
			BillingData: user.BillingData,
			AmountETH:   user.BillingData.ETHAmount,
			AddressXMR:  user.BillingData.XMRAddress,
			AddressETH:  admin.EthAddress,
			UserID:      user.UserID,
			DateCreated: time.Now().UTC(),
		}

		tmp, _ := qrcode.Encode(fmt.Sprintf("monero:%s?tx_amount=%s", d.AddressXMR, xmrNeededFormatted), qrcode.Low, 320)
		d.QRB64XMR = base64.StdEncoding.EncodeToString(tmp)

		donationLink := fmt.Sprintf("ethereum:%s?value=%s", admin.EthAddress, d.AmountETH)
		tmp, _ = qrcode.Encode(donationLink, qrcode.Low, 320)
		d.QRB64ETH = base64.StdEncoding.EncodeToString(tmp)

		err := billPayTemplate.Execute(w, d)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}
}

func getNewAccountETHPrice() string {
	ethPrice, _ := strconv.ParseFloat(fmt.Sprintf("%.18f", (15.00/prices.Ethereum)), 64)
	ethStr := utils.FuzzDono(ethPrice, "ETH")
	ethStr_, _ := utils.StandardizeFloatToString(ethStr)
	return ethStr_
}
func getNewAccountXMRPrice() string {
	xmrPrice, _ := strconv.ParseFloat(fmt.Sprintf("%.5f", (15.00/prices.Monero)), 64)
	xmrStr, _ := utils.StandardizeFloatToString(xmrPrice)
	return xmrStr
}

func getXMRAmountInUSD(usdAmount float64) string {
	xmrPrice, _ := strconv.ParseFloat(fmt.Sprintf("%.5f", (usdAmount/prices.Monero)), 64)
	xmrStr, _ := utils.StandardizeFloatToString(xmrPrice)
	return xmrStr
}

func getETHAmountInUSD(usdAmount float64) string {
	ethPrice, _ := strconv.ParseFloat(fmt.Sprintf("%.18f", (usdAmount/prices.Ethereum)), 64)
	ethStr := utils.FuzzDono(ethPrice, "ETH")
	ethStr_, _ := utils.StandardizeFloatToString(ethStr)
	return ethStr_
}

func getNewAccountXMR() (string, string) {
	payload := strings.NewReader(`{"jsonrpc":"2.0","id":"0","method":"make_integrated_address"}`)
	userID := 1
	portID := getPortID(xmrWallets, userID)

	found := true
	if portID == -100 {
		found = false
	}

	if found {
		fmt.Println("Port ID for user", userID, "is", portID)
	} else {
		fmt.Println("Port ID not found for user", userID)
	}

	rpcURL_ := "http://127.0.0.1:" + strconv.Itoa(portID) + "/json_rpc"

	req, err := http.NewRequest("POST", rpcURL_, payload)
	if err != nil {
		log.Println("ERROR CREATING req:", err)
		return "", ""
	}

	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("ERROR SENDING REQUEST:", err)
		return "", ""
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Println("ERROR: Non-200 response code received:", res.StatusCode)
		return "", ""
	}

	resp := &utils.RPCResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		log.Println("ERROR DECODING RESPONSE:", err)
		return "", ""
	}

	PayID := html.EscapeString(resp.Result.PaymentID)

	PayAddress := html.EscapeString(resp.Result.IntegratedAddress)

	log.Println("RETURNING XMR PAYID:", PayID)
	return PayID, PayAddress
}

func createNewPendingUser(username string, password string) (utils.PendingUser, error) {
	log.Println("begin createNewPendingUser()")
	user_, _ := getUserByUsernameCached("admin")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return utils.PendingUser{}, err
	}
	PayID, PayAddress := getNewAccountXMR()
	user := utils.PendingUser{
		Username:       username,
		HashedPassword: hashedPassword,
		ETHAddress:     user_.EthAddress,
		XMRAddress:     PayAddress,
		ETHNeeded:      getNewAccountETHPrice(),
		XMRNeeded:      getNewAccountXMRPrice(),
		XMRPayID:       PayID,
	}

	err = createPendingUser(user)
	if err != nil {
		log.Println("createPendingUser:", err)
		return utils.PendingUser{}, err
	}
	// Get the ID of the newly inserted user
	row := db.QueryRow(`SELECT last_insert_rowid()`)
	err = row.Scan(&user.ID)
	if err != nil {
		return utils.PendingUser{}, err
	}
	pendingGlobalUsers[user.ID] = user
	log.Println("finish createNewPendingUser() without error")
	return user, nil

}

func createPendingUser(user utils.PendingUser) error {
	_, err := db.Exec(`
        INSERT INTO pendingusers (username, HashedPassword, XMRPayID, XMRNeeded, ETHNeeded)
        VALUES (?, ?, ?, ?, ?)
    `, user.Username, user.HashedPassword, user.XMRPayID, user.XMRNeeded, user.ETHNeeded)
	if err != nil {
		return err
	}

	// Get the ID of the newly inserted user
	row := db.QueryRow(`SELECT last_insert_rowid()`)
	err = row.Scan(&user.ID)
	if err != nil {
		return err
	}

	return nil
}

func getNewUser(username string, hashedPassword []byte) utils.User {

	ce := utils.CryptosEnabled{
		XMR:   false,
		SOL:   false,
		ETH:   false,
		PAINT: false,
		HEX:   false,
		MATIC: false,
		BUSD:  false,
		SHIB:  false,
		PNK:   false,
	}

	user := utils.User{
		Username:          username,
		HashedPassword:    hashedPassword,
		CryptosEnabled:    ce,
		EthAddress:        "0x5b5856dA280e592e166A1634d353A53224ed409c",
		SolAddress:        "adWqokePHcAbyF11TgfvvM1eKax3Kxtnn9sZVQh6fXo",
		HexcoinAddress:    "0x5b5856dA280e592e166A1634d353A53224ed409c",
		XMRWalletPassword: "",
		MinDono:           3,
		MinMediaDono:      5,
		MediaEnabled:      true,
		DonoGIF:           "default.gif",
		DonoSound:         "default.mp3",
		AlertURL:          utils.GenerateUniqueURL(),
		WalletUploaded:    false,
		Links:             "",
		DateEnabled:       time.Now().UTC(),
	}
	return user
}

func createNewUserFromPending(user_ utils.PendingUser) error {
	log.Println("running createNewUserFromPending")

	user := getNewUser(user_.Username, user_.HashedPassword)
	userID := createUser(user)
	if userID != 0 {
		createNewOBS(db, userID, "default message", 100.00, 50.00, 5, user.DonoGIF, user.DonoSound, "test_voice")
		log.Println("createNewUserFromPending() succeeded, so OBS row was created. Deleting pending user from pendingusers table")
		err := deletePendingUser(user_)
		if err != nil {
			return err
		}
	} else {
		log.Println("createNewUserFromPending() didn't succeed, so OBS row wasn't created. Pending user remains in DB")
	}

	log.Println("finished createNewUserFromPending()")

	return nil
}

func deletePendingUser(user utils.PendingUser) error {
	delete(pendingGlobalUsers, user.ID)
	_, err := db.Exec(`DELETE FROM pendingusers WHERE id = ?`, user.ID)
	if err != nil {
		return err
	}

	return nil
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	user, validUser := getUserByUsernameCached(username)

	if r.Method != http.MethodPost || !validUser {
		// Redirect to the payment page if the request is not a POST request
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get the user's IP address
	ip := getIPAddress(r)
	log.Println("dono ip", ip)

	// Get form values
	fCrypto := r.FormValue("crypto")
	fAmount := r.FormValue("amount")
	fName := r.FormValue("name")
	fMessage := r.FormValue("message")
	fMedia := r.FormValue("media")
	fShowAmount := r.FormValue("showAmount")
	encrypted_ip := encryptIP(ip)
	log.Println("encrypted_ip", encrypted_ip)

	matching_ips := utils.CheckPendingDonosFromIP(pending_donos, ip)

	log.Println("Waiting pending donos from this IP:", matching_ips)
	if matching_ips >= 9 {
		http.Redirect(w, r, "/overflow", http.StatusSeeOther)
		return
	}

	if fAmount == "" {
		fAmount = "0"
	}
	amount, err := strconv.ParseFloat(fAmount, 64)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("fAmount", fAmount)
	fmt.Println("Amount", amount)

	minValues := map[string]float64{
		"XMR":   user.MinXmr,
		"SOL":   user.MinSol,
		"ETH":   user.MinEth,
		"PAINT": user.MinPaint,
		"HEX":   user.MinHex,
		"MATIC": user.MinMatic,
		"BUSD":  user.MinBusd,
		"SHIB":  user.MinShib,
		"PNK":   user.MinPnk,
	}

	if minValue, ok := minValues[fCrypto]; ok && amount < minValue {
		amount = minValue
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

	var s utils.CryptoSuperChat
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

	USDAmount := getUSDValue(amount, fCrypto)
	if fCrypto == "XMR" {
		createNewXMRDono(s.Name, s.Message, s.Media, amount, encrypted_ip)
		handleMoneroPayment(w, &s, params, amount, encrypted_ip, showAmount, USDAmount, user.UserID)
	} else if fCrypto == "SOL" {
		new_dono := createNewSolDono(s.Name, s.Message, s.Media, utils.FuzzDono(amount, "SOL"), encrypted_ip)
		handleSolanaPayment(w, &s, params, new_dono.Name, new_dono.Message, new_dono.AmountNeeded, showAmount, media, encrypted_ip, USDAmount, user.UserID)
	} else {
		s.Currency = fCrypto
		new_dono := createNewEthDono(s.Name, s.Message, s.Media, amount, fCrypto, encrypted_ip)
		handleEthereumPayment(w, &s, new_dono.Name, new_dono.Message, new_dono.AmountNeeded, showAmount, new_dono.MediaURL, fCrypto, encrypted_ip, USDAmount, user.UserID)
	}
}

func createNewSolDono(name string, message string, mediaURL string, amountNeeded float64, encrypted_ip string) utils.SuperChat {
	new_dono := utils.CreatePendingDono(name, message, mediaURL, amountNeeded, "SOL", encrypted_ip)
	pending_donos = utils.AppendPendingDono(pending_donos, new_dono)

	return new_dono
}

func createNewXMRDono(name string, message string, mediaURL string, amountNeeded float64, encrypted_ip string) {
	new_dono := utils.CreatePendingDono(name, message, mediaURL, amountNeeded, "XMR", encrypted_ip)
	pending_donos = utils.AppendPendingDono(pending_donos, new_dono)
}

func checkDonationStatusHandler(w http.ResponseWriter, r *http.Request) {
	donationIDStr := r.FormValue("donation_id") // Get the donation ID from the query string
	donationID, err := strconv.Atoi(donationIDStr)
	log.Println("User Page Checking DonationID:", donationID)
	if err != nil {
		http.Error(w, "Invalid donation ID", http.StatusBadRequest)
		return
	}

	completed := isDonoFulfilled(donationID)
	if completed {
		fmt.Fprintf(w, `true`) // Return the status as a JSON response
	} else {
		fmt.Fprintf(w, `false`) // Return the status as a JSON response
	}
}

func isDonoFulfilled(donoID int) bool {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Retrieve the dono with the given ID
	row := db.QueryRow("SELECT fulfilled FROM donos WHERE dono_id = ?", donoID)

	var fulfilled bool
	err = row.Scan(&fulfilled)
	if err != nil {
		panic(err)
	}

	return fulfilled
}

func ethToWei(ethStr string) *big.Int {
	etherValue := big.NewFloat(1000000000000000000)
	f, err := strconv.ParseFloat(ethStr, 64)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	number := big.NewFloat(f)

	weiValue := new(big.Int)
	weiValue, _ = weiValue.SetString(number.Mul(number, etherValue).Text('f', 0), 10)

	return weiValue
}

func getEthAddressByID(userID int) string {
	if user, ok := globalUsers[userID]; ok {
		log.Println("Got userID:", user.UserID, "Returned:", user.EthAddress)
		return user.EthAddress
	}
	log.Println("Got userID:", userID, "No user found")
	return ""
}

func getSolAddressByID(userID int) string {
	if user, ok := globalUsers[userID]; ok {
		log.Println("Got userID:", user.UserID, "Returned:", user.SolAddress)
		return user.SolAddress
	}
	log.Println("Got userID:", userID, "No user found")
	return ""
}

func getPortID(xmrWallets [][]int, userID int) int {
	for _, innerList := range xmrWallets {
		if innerList[0] == userID {
			return innerList[1]
		}
	}
	return -100
}

func handleEthereumPayment(w http.ResponseWriter, s *utils.CryptoSuperChat, name_ string, message_ string, amount_ float64, showAmount_ bool, media_ string, fCrypto string, encrypted_ip string, USDAmount float64, userID int) {
	address := getEthAddressByID(userID)
	log.Println("handleEthereumPayment() address:", address)

	decimals, _ := utils.GetCryptoDecimalsByCode(fCrypto)
	donoStr := fmt.Sprintf("%.*f", decimals, amount_)
	log.Println("handleEthereumPayment() donoStr:", address)

	s.Amount = donoStr
	log.Println("handleEthereumPayment() donoStr:", s.Amount)

	if fCrypto != "ETH" {
		s.ContractAddress, _ = utils.GetCryptoContractByCode(fCrypto)
	} else {
		s.ContractAddress = "ETH"
	}

	if name_ == "" {
		s.Name = "Anonymous"
		name_ = s.Name
	} else {
		s.Name = html.EscapeString(truncateStrings(condenseSpaces(name_), NameMaxChar))
	}

	s.WeiAmount = ethToWei(donoStr)
	s.Media = html.EscapeString(media_)
	s.Address = address

	donationLink := fmt.Sprintf("ethereum:%s?value=%s", address, donoStr)

	tmp, _ := qrcode.Encode(donationLink, qrcode.Low, 320)
	s.QRB64 = base64.StdEncoding.EncodeToString(tmp)
	s.DonationID = createNewDono(userID, address, s.Name, s.Message, s.Amount, fCrypto, encrypted_ip, showAmount_, USDAmount, media_)
	err := payTemplate.Execute(w, s)
	if err != nil {
		fmt.Println(err)
	}
}

func handleSolanaPayment(w http.ResponseWriter, s *utils.CryptoSuperChat, params url.Values, name_ string, message_ string, amount_ float64, showAmount_ bool, media_ string, encrypted_ip string, USDAmount float64, userID int) {
	// Get Solana address and desired balance from request
	address := getSolAddressByID(userID)
	donoStr := fmt.Sprintf("%.*f", 9, amount_)

	s.Amount = donoStr

	if name_ == "" {
		s.Name = "Anonymous"
	} else {
		s.Name = html.EscapeString(truncateStrings(condenseSpaces(name_), NameMaxChar))
	}

	s.Media = html.EscapeString(media_)
	s.PayID = address
	s.Address = address
	s.Currency = "SOL"

	params.Add("id", s.Address)

	s.CheckURL = params.Encode()

	tmp, _ := qrcode.Encode("solana:"+address+"?amount="+donoStr, qrcode.Low, 320)
	s.QRB64 = base64.StdEncoding.EncodeToString(tmp)

	s.DonationID = createNewDono(userID, address, name_, message_, s.Amount, "SOL", encrypted_ip, showAmount_, USDAmount, media_)

	err := payTemplate.Execute(w, s)
	if err != nil {
		fmt.Println(err)
	}
}

func handleMoneroPayment(w http.ResponseWriter, s *utils.CryptoSuperChat, params url.Values, amount float64, encrypted_ip string, showAmount bool, USDAmount float64, userID int) {
	payload := strings.NewReader(`{"jsonrpc":"2.0","id":"0","method":"make_integrated_address"}`)
	portID := getPortID(xmrWallets, userID)

	found := true
	if portID == -100 {
		found = false
	}

	if found {
		fmt.Println("Port ID for user", userID, "is", portID)
	} else {
		fmt.Println("Port ID not found for user", userID)
	}

	rpcURL_ := "http://127.0.0.1:" + strconv.Itoa(portID) + "/json_rpc"

	req, err := http.NewRequest("POST", rpcURL_, payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("ERROR CREATING")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("ERROR CREATING")
	}

	resp := &utils.RPCResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		fmt.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("ERROR CREATING")
	}

	s.PayID = html.EscapeString(resp.Result.PaymentID)
	s.Address = html.EscapeString(resp.Result.IntegratedAddress)
	s.Currency = "XMR"
	params.Add("id", resp.Result.PaymentID)
	params.Add("address", resp.Result.IntegratedAddress)
	s.CheckURL = params.Encode()

	tmp, _ := qrcode.Encode(fmt.Sprintf("monero:%s?tx_amount=%s", resp.Result.IntegratedAddress, s.Amount), qrcode.Low, 320)
	s.QRB64 = base64.StdEncoding.EncodeToString(tmp)

	s.DonationID = createNewDono(userID, s.PayID, s.Name, s.Message, s.Amount, "XMR", encrypted_ip, showAmount, USDAmount, s.Media)

	err = payTemplate.Execute(w, s)
	if err != nil {
		fmt.Println(err)
	}
}
