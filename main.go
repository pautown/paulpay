// TODO:
/*
  Send solana once it has been recieved to non-costodial address
  Change CSV storage of information regarding donos to database
  Add config screen for setting non-costodial addresses
  Add media link for donos
  Modify OBS display code
  Add OBS media display
  Refactor
  Refactor
  Refactor again
  Get project done in 21.2571429 hours * $70/hr
  13.2571429 hours remain.

*/

package main

import (

	// get version number of sol
	"context"
	"crypto/ed25519"

	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"database/sql"
	_ "github.com/mattn/go-sqlite3"

	"github.com/portto/solana-go-sdk/client"
	"github.com/portto/solana-go-sdk/rpc"
	"github.com/portto/solana-go-sdk/types"
	qrcode "github.com/skip2/go-qrcode"



	"crypto/rand"
	"github.com/google/uuid"

	"golang.org/x/crypto/bcrypt"
)

var USDMinimum float64 = 5
var ScamThreshold float64 = 0.005 // MINIMUM DONATION AMOUNT
var MediaMin float64 = 0.025      // Currently unused
var MessageMaxChar int = 250
var NameMaxChar int = 25
var rpcURL string = "http://127.0.0.1:28088/json_rpc"
var coingeckoURL string = "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd"
var username string = "admin"                // chat log /view page
var AlertWidgetRefreshInterval string = "10" //seconds

var addressSliceSolana []AddressSolana

// this is the password for both the /view page and the OBS /alert page
// example OBS url: https://example.com/alert?auth=adminadmin
var password string = "adminadmin"
var checked string = ""



var indexTemplate *template.Template
var payTemplate *template.Template
var alertTemplate *template.Template
var viewTemplate *template.Template

var loginTemplate *template.Template
var incorrectLoginTemplate *template.Template
var userTemplate *template.Template
var logoutTemplate *template.Template
var incorrectPasswordTemplate *template.Template



// Mainnet
//var c = client.NewClient(rpc.MainnetRPCEndpoint)

// Devnet
var c = client.NewClient(rpc.DevnetRPCEndpoint)



type User struct {
	UserID               int
	Username             string
	HashedPassword       []byte
	Timezone             string
	EthAddress           string
	SolAddress           string
	HexcoinAddress       string
	XMRWalletPassword    string
	MinDono              int
	MinMediaDono         int
	MediaEnabled         bool
	CreationDatetime     string
	ModificationDatetime string
}

type UserPageData struct {
	ErrorMessage string
}

var db *sql.DB
var userSessions = make(map[string]int)

func MakeRequest(URL string) string {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", URL, nil)
	req.Header.Set("Header_Key", "Header_Value")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Err is", err)
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)
	response := string(resBody)

	return response
}

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

type configJson struct {
	MinimumDonation  float64  `json:"MinimumDonation"`
	MaxMessageChars  int      `json:"MaxMessageChars"`
	MaxNameChars     int      `json:"MaxNameChars"`
	RPCWalletURL     string   `json:"RPCWalletURL"`
	WebViewUsername  string   `json:"WebViewUsername"`
	WebViewPassword  string   `json:"WebViewPassword"`
	OBSWidgetRefresh string   `json:"OBSWidgetRefresh"`
	Checked          bool     `json:"ShowAmountCheckedByDefault"`
}

type checkPage struct {
	Addy     string
	PayID    string
	Received float64
	Meta     string
	Name     string
	Msg      string
	Receipt  string
	Media    string
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

type csvLog struct {
	ID            string
	Name          string
	Message       string
	Amount        string
	DisplayToggle string
	Refresh       string
}

type indexDisplay struct {
	MaxChar int
	MinAmnt float64
	Checked string
}

type viewPageData struct {
	ID      []string
	Name    []string
	Message []string
	Amount  []string
	Display []string
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



func main() {
	log.Println("Starting server")
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// create users table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		UserID INTEGER PRIMARY KEY AUTOINCREMENT,
		Username TEXT UNIQUE,
		HashedPassword BLOB,
		Timezone TEXT,
		EthAddress TEXT,
		SolAddress TEXT,
		HexcoinAddress TEXT,
		XMRWalletPassword TEXT,
		MinDono INTEGER,
		MinMediaDono INTEGER,
		MediaEnabled BOOLEAN,
		CreationDatetime TEXT,
		ModificationDatetime TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// create admin user if not exists
	adminUser := User{
		Username:          "admin",
		XMRWalletPassword: "",
		MinDono:           0,
		MinMediaDono:      0,
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

	



	// create a RPC client
	fmt.Println(reflect.TypeOf(c))

	// get the current running Solana version
	response, err := c.GetVersion(context.TODO())
	if err != nil {
		panic(err)
	}

	fmt.Println("version", response.SolanaCore)

	fmt.Println(fmt.Sprintf("OBS Alert path: /alert?auth=%s", password))

	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/style.css")
	})
	http.HandleFunc("/xmr.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/xmr.svg")
	})

	http.HandleFunc("/sol.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/sol.svg")
	})

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/pay", paymentHandler)
	http.HandleFunc("/alert", alertHandler)
	http.HandleFunc("/view", viewHandler)


	// serve login and user interface pages
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/incorrect_login", incorrectLoginHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/changepassword", changePasswordHandler)


	indexTemplate, _ = template.ParseFiles("web/index.html")
	payTemplate, _ = template.ParseFiles("web/pay.html")
	alertTemplate, _ = template.ParseFiles("web/alert.html")
	viewTemplate, _ = template.ParseFiles("web/view.html")



	loginTemplate, _ = template.ParseFiles("web/login.html")
	incorrectLoginTemplate, _ = template.ParseFiles("web/incorrect_login.html")
	userTemplate, _ = template.ParseFiles("web/user.html")
	logoutTemplate, _ = template.ParseFiles("web/logout.html")
	incorrectPasswordTemplate, _ = template.ParseFiles("web/password_change_failed.html")


	err = http.ListenAndServe(":8900", nil)
	if err != nil {
		panic(err)
	}
}

// create a new user
func createUser(user User) error {
	statement := `
		INSERT INTO users (Username, HashedPassword, Timezone, EthAddress, SolAddress, HexcoinAddress,
			XMRWalletPassword, MinDono, MinMediaDono, MediaEnabled, CreationDatetime, ModificationDatetime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`
	_, err := db.Exec(statement, user.Username, user.HashedPassword, user.Timezone, user.EthAddress,
		user.SolAddress, user.HexcoinAddress, user.XMRWalletPassword, user.MinDono, user.MinMediaDono,
		user.MediaEnabled)
	return err
}

// update an existing user
func updateUser(user User) error {
	statement := `
		UPDATE users
		SET Username=?, HashedPassword=?, Timezone=?, EthAddress=?, SolAddress=?, HexcoinAddress=?,
			XMRWalletPassword=?, MinDono=?, MinMediaDono=?, MediaEnabled=?, ModificationDatetime=datetime('now')
		WHERE UserID=?
	`
	_, err := db.Exec(statement, user.Username, user.HashedPassword, user.Timezone, user.EthAddress,
		user.SolAddress, user.HexcoinAddress, user.XMRWalletPassword, user.MinDono, user.MinMediaDono,
		user.MediaEnabled, user.UserID)
	return err
}

// get a user by their username
func getUserByUsername(username string) (User, error) {
	var user User
	row := db.QueryRow("SELECT * FROM users WHERE Username=?", username)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.Timezone, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime)
	if err != nil {
		return User{}, err
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
	row := db.QueryRow("SELECT * FROM users WHERE UserID=?", userID)
	err := row.Scan(&user.UserID, &user.Username, &user.HashedPassword, &user.Timezone, &user.EthAddress,
		&user.SolAddress, &user.HexcoinAddress, &user.XMRWalletPassword, &user.MinDono, &user.MinMediaDono,
		&user.MediaEnabled, &user.CreationDatetime, &user.ModificationDatetime)
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
			Name:     "session",
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

// handle requests to modify user data
func userHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
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
		user.Timezone = r.FormValue("timezone")
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
	sessionToken, err := r.Cookie("session")
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

func renderChangePasswordForm(w http.ResponseWriter, data UserPageData) {
	tmpl, err := template.ParseFiles("web/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// invalidate session token
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// redirect user to login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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
	sessionToken, err := r.Cookie("session")
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
	//create a new wallet using
	wallet := types.NewAccount()

	// display the wallet public and private keys
	//fmt.Println("Wallet Address:", wallet.PublicKey.ToBase58())
	//fmt.Println("Wallet Private Key:", wallet.PrivateKey)

	address := AddressSolana{}
	address.KeyPublic = wallet.PublicKey.ToBase58()
	address.KeyPrivate = wallet.PrivateKey
	address.DonoName = dName
	address.DonoAmount = dAmount
	address.DonoString = dString
	address.DonoAnon = dAnon
	//addressByte, _ := json.Marshal(address)

	//fmt.Println("Json OBJ: " + string(addressByte))
	addToAddressSliceSolana(address)

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

func viewHandler(w http.ResponseWriter, r *http.Request) {
	var a viewPageData
	var displayTemp string

	u, p, ok := r.BasicAuth()
	if !ok {
		w.Header().Add("WWW-Authenticate", `Basic realm="Give username and password"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if (u == username) && (p == password) {
		csvFile, err := os.Open("log/superchats.csv")
		if err != nil {
			fmt.Println(err)
		}

		defer func(csvFile *os.File) {
			err := csvFile.Close()
			if err != nil {
				fmt.Println(err)
			}
		}(csvFile)

		csvLines, err := csv.NewReader(csvFile).ReadAll()
		if err != nil {
			fmt.Println(err)
		}

		for _, line := range csvLines {
			a.ID = append(a.ID, line[0])
			a.Name = append(a.Name, line[1])
			a.Message = append(a.Message, line[2])
			a.Amount = append(a.Amount, line[3])
			displayTemp = fmt.Sprintf("<h3><b>%s</b> sent <b>%s</b> XMR:</h3><p>%s</p>", html.EscapeString(line[1]), html.EscapeString(line[3]), line[2])
			a.Display = append(a.Display, displayTemp)
		}

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return // return http 401 unauthorized error
	}
	reverse(a.Display)
	err := viewTemplate.Execute(w, a)
	if err != nil {
		fmt.Println(err)
	}
}


func addPaymentToLog(name, message, media, currency string, amount float64, anon bool) {
	//var datetime = getCurrentDateTime()
	// ADD PAYMENTS TO LOG
	if currency == "SOL" {

	} else if currency == "XMR" {

	}

}

func getCurrentDateTime() string {
	now := time.Now()
	return now.Format("2006-01-02 15:04:05")
}




func indexHandler(w http.ResponseWriter, _ *http.Request) {
	var i indexDisplay
	i.MaxChar = MessageMaxChar
	i.MinAmnt = ScamThreshold
	i.Checked = checked
	err := indexTemplate.Execute(w, i)
	if err != nil {
		fmt.Println(err)
	}
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	var v csvLog
	v.Refresh = AlertWidgetRefreshInterval
	if r.FormValue("auth") == password {

		csvFile, err := os.Open("log/alertqueue.csv")
		if err != nil {
			fmt.Println(err)
		}

		csvLines, err := csv.NewReader(csvFile).ReadAll()
		if err != nil {
			fmt.Println(err)
		}
		defer func(csvFile *os.File) {
			err := csvFile.Close()
			if err != nil {
				fmt.Println(err)
			}
		}(csvFile)

		// Remove top line of CSV file after displaying it
		if csvLines != nil {
			popFile, _ := os.OpenFile("log/alertqueue.csv", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			popFirst := csvLines[1:]
			w := csv.NewWriter(popFile)
			err := w.WriteAll(popFirst)
			if err != nil {
				fmt.Println(err)
			}
			defer func(popFile *os.File) {
				err := popFile.Close()
				if err != nil {
					fmt.Println(err)
				}
			}(popFile)
			v.ID = csvLines[0][0]
			v.Name = csvLines[0][1]
			v.Message = csvLines[0][2]
			v.Amount = csvLines[0][3]
			v.DisplayToggle = ""
		} else {
			v.DisplayToggle = "display: none;"
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return // return http 401 unauthorized error
	}
	err := alertTemplate.Execute(w, v)
	if err != nil {
		fmt.Println(err)
	}
}

func getSolanaBalance(address string, amount float64) bool {

	balance, err := c.GetBalance(
		context.TODO(), // request context
		address,        // wallet to fetch balance for
	)

	if err != nil {
		log.Fatalln("get balance error", err)
	}
	var realBalance = float64(balance / 1e9)
	if realBalance >= amount { // if donation has been fulfilled
		return true
	} else {

		return false
	}

	//return balance >= uint64(amount*math.Pow10(9)), nil
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {

	//log.Fatalln("monState: ", monState)
	var s superChat
	params := url.Values{}
	var resp *rpcResponse // Declare resp outside the if statement
	var moneroBool = false
	if r.FormValue("mon") == "true" {
		moneroBool = true
	}

	if moneroBool {
		payload := strings.NewReader(`{"jsonrpc":"2.0","id":"0","method":"make_integrated_address"}`)
		req, err := http.NewRequest("POST", rpcURL, payload)
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(req)
			if err == nil {
				resp = &rpcResponse{}
				if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
					fmt.Println(err.Error())
				}

				s.Amount = html.EscapeString(r.FormValue("amount"))
				if r.FormValue("amount") == "" {
					s.Amount = fmt.Sprint(ScamThreshold)
				}
				if r.FormValue("name") == "" {
					s.Name = "Anonymous"
				} else {
					s.Name = html.EscapeString(truncateStrings(condenseSpaces(r.FormValue("name")), NameMaxChar))
				}
				s.Message = html.EscapeString(truncateStrings(condenseSpaces(r.FormValue("message")), MessageMaxChar))
				s.Media = html.EscapeString(r.FormValue("media"))
				s.PayID = html.EscapeString(resp.Result.PaymentID)
				s.Address = resp.Result.IntegratedAddress

				params.Add("id", resp.Result.PaymentID)
				params.Add("name", s.Name)
				params.Add("msg", r.FormValue("message"))
				params.Add("media", condenseSpaces(s.Media))
				params.Add("show", html.EscapeString(r.FormValue("showAmount")))
				s.CheckURL = params.Encode()

				tmp, _ := qrcode.Encode(fmt.Sprintf("monero:%s?tx_amount=%s", resp.Result.IntegratedAddress, s.Amount), qrcode.Low, 320)
				s.QRB64 = base64.StdEncoding.EncodeToString(tmp)

				err := payTemplate.Execute(w, s)
				if err != nil {
					fmt.Println(err)
				}
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				return // return http 401 unauthorized error
			}
		}
	} else { //if paying with solana

		s.Amount = html.EscapeString(r.FormValue("amount"))
		if r.FormValue("amount") == "" {
			s.Amount = fmt.Sprint(ScamThreshold)
		}
		if r.FormValue("name") == "" {
			s.Name = "Anonymous"
		} else {
			s.Name = html.EscapeString(truncateStrings(condenseSpaces(r.FormValue("name")), NameMaxChar))
		}
		s.Message = html.EscapeString(truncateStrings(condenseSpaces(r.FormValue("message")), MessageMaxChar))
		s.Media = html.EscapeString(r.FormValue("media"))

		params.Add("name", s.Name)
		params.Add("msg", r.FormValue("message"))
		params.Add("media", condenseSpaces(s.Media))
		params.Add("show", html.EscapeString(r.FormValue("showAmount")))

		amountStr := r.FormValue("amount")
		amount, err := strconv.ParseFloat(amountStr, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		showAmount, err := strconv.ParseBool(html.EscapeString(r.FormValue("showAmount")))
		if err != nil {
			// handle the error here
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var wallet_ = createWalletSolana(s.Name, r.FormValue("message"), amount, showAmount)
		// Get Solana address and desired balance from request
		address := wallet_.KeyPublic

		// Check balance
		//hasBalance := checkSolanaBalance(address, amount)

		donoStr := fmt.Sprintf("%.2f", wallet_.DonoAmount)

		// Wallet won't have what's needed, so now we display the dono page for the person to donate. Just like the monero page.

		s.Amount = donoStr
		if donoStr == "" {
			s.Amount = fmt.Sprint(ScamThreshold)
			donoStr = s.Amount
		}

		if wallet_.DonoName == "" {
			s.Name = "Anonymous"
			wallet_.DonoName = s.Name
		} else {
			s.Name = html.EscapeString(truncateStrings(condenseSpaces(wallet_.DonoName), NameMaxChar))
		}

		s.Message = wallet_.DonoString
		s.Media = html.EscapeString(r.FormValue("media"))
		s.PayID = wallet_.KeyPublic
		s.Address = wallet_.KeyPublic
		s.IsSolana = !moneroBool

		params.Add("id", s.Address)
		params.Add("amount", donoStr)
		params.Add("msg", r.FormValue("message"))
		params.Add("media", condenseSpaces(s.Media))
		params.Add("show", html.EscapeString(r.FormValue("showAmount")))
		s.CheckURL = params.Encode()

		tmp, _ := qrcode.Encode("solana:"+address+"?amount="+donoStr, qrcode.Low, 320)
		s.QRB64 = base64.StdEncoding.EncodeToString(tmp)
		err = payTemplate.Execute(w, s)
		if err != nil {
			fmt.Println(err)
		}

	}
}
