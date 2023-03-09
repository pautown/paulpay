package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Check if the database and tables exist, and create them if they don't
	err = createDatabaseIfNotExists(db)
	if err != nil {
		panic(err)
	}

	checkDonos() 
	
}

func checkDonos(){ // Check all donos for newly fulfilled donos
	// Check for unfulfilled donos and add newly fulfilled donos to a slice
	fulfilledDonos := checkUnfulfilledDonos()
	// Add fulfilled donos to the Queue table
	for _, dono := range fulfilledDonos {
		err := createNewQueueEntry(db, dono.Name, dono.AmountSent, dono.CurrencyType)
		if err != nil {
			panic(err)
		}
	}
}

func createDatabaseIfNotExists(db *sql.DB) error {
	// Check if the donos table exists
	var donosTableExists bool
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='donos'").Scan(&donosTableExists)
	if err != nil {
		return err
	}

	// Check if the queue table exists
	var queueTableExists bool
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='queue'").Scan(&queueTableExists)
	if err != nil {
		return err
	}

	// Check if the users table exists
	var usersTableExists bool
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&usersTableExists)
	if err != nil {
		return err
	}

	// If neither table exists, create them
	if !donosTableExists && !queueTableExists && !usersTableExists {
		_, err = db.Exec(`
			CREATE TABLE donos (
				dono_id INTEGER PRIMARY KEY,
				user_id INTEGER,
				dono_name TEXT,
				dono_message TEXT,
				amount_to_send FLOAT,			
				amount_sent FLOAT,
				currency_type TEXT,
				anon_dono BOOL,
				fulfilled BOOL,
				created_at DATETIME,
				updated_at DATETIME,
				FOREIGN KEY(user_id) REFERENCES users(id)
			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE queue (
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
			CREATE TABLE users (
				id INTEGER PRIMARY KEY,
				username TEXT,
				password TEXT,
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

		// Create the admin user
		_, err = db.Exec(`
			INSERT INTO users (
				username,
				password,
				min_donation_threshold,
				min_media_threshold,
				media_enabled,
				created_at,
				modified_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, "admin", "hunter123", 0.0, 0.0, false, time.Now(), time.Now())
		if err != nil {
			return err
		}
	}

	return nil
}



func createNewQueueEntry(db *sql.DB, name string, message string, amount float64, currency string) error {
	_, err := db.Exec(`
		INSERT INTO queue (name, message, amount, currency) VALUES (?, ?, ?)
	`, name, message, amount, currency)
	if err != nil {
		return err
	}
	return nil
}

func createNewDono(user_id int, dono_name string, dono_message amount_to_send float64, currencyType string, anon_dono bool) {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Get current time
	createdAt := time.Now().UTC()

	// Execute the SQL INSERT statement
	_, err = db.Exec(`
		INSERT INTO donos (
			user_id,
			dono_name,
			dono_message,
			amount_to_send,
			amount_sent,
			currency_type,
			anon_dono,
			fulfilled,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, user_id, dono_name, dono_message, amount_to_send, 0.0, currencyType, anon_dono, false, createdAt, createdAt)
	if err != nil {
		panic(err)
	}
}

type Dono struct {
	ID            int
	UserID        int
	Name          string
	Message 	  string
	AmountToSend  float64
	AmountSent    float64
	CurrencyType  string
	AnonDono      bool
	Fulfilled     bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func checkUnfulfilledDonos() []Dono {
	// Open a new database connection
	db, err := sql.Open("sqlite3", "./users.db")
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

	// Loop through the unfulfilled donos and check their status
	var fulfilledDonos []Dono
	for rows.Next() {
		var dono Dono
		err := rows.Scan(&dono.ID, &dono.UserID, &dono.Name, &dono.Message, &dono.AmountToSend, &dono.AmountSent, &dono.CurrencyType, &dono.AnonDono, &dono.Fulfilled, &dono.CreatedAt, &dono.UpdatedAt)
		if err != nil {
			panic(err)
		}

		if dono.CurrencyType == "XMR" {
			dono.AmountSent = getXMRBalance(dono.Address)
		} else if dono.CurrencyType == "SOL" {
			dono.AmountSent = getSOLBalance(dono.Address)
		}

		if dono.AmountSent >= dono.AmountToSend {
			dono.AmountSent = getCurrentBalance(dono.Address)
			dono.Fulfilled = true
			fulfilledDonos = append(fulfilledDonos, dono)
		}
	}

	// Mark the newly fulfilled donos as fulfilled in the donos table
	for _, dono := range fulfilledDonos {
		_, err := db.Exec(`UPDATE donos SET fulfilled = true, amount_sent = ? WHERE dono_id = ?`, dono.AmountSent, dono.ID)
		if err != nil {
		panic(err)
		}
	}
return fulfilledDonos
}



func getSolanaBalance(address string) (float64, error) {
    balance, err := c.GetBalance(
        context.TODO(), // request context
        address,        // wallet to fetch balance for
    )
    if err != nil {
        return 0, err
    }
    return float64(balance) / 1e9, nil
}


func getXMRBalance(address string) (float64, error) {
    // Construct the URL for the Monero RPC endpoint
    url := "http://127.0.0.1:18081/json_rpc"

    // Create the JSON request payload for the RPC call
    rpcRequest := map[string]interface{}{
        "jsonrpc": "2.0",
        "id":      "0",
        "method":  "get_balance",
        "params": map[string]interface{}{
            "address": address,
        },
    }

    // Convert the request payload to JSON format
    payload, err := json.Marshal(rpcRequest)
    if err != nil {
        return 0, err
    }

    // Make the HTTP POST request to the Monero RPC endpoint
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    // Parse the JSON response
    var rpcResponse map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&rpcResponse)
    if err != nil {
        return 0, err
    }

    // Check if the RPC call was successful
    if rpcResponse["error"] != nil {
        return 0, fmt.Errorf("RPC call failed: %s", rpcResponse["error"].(map[string]interface{})["message"])
    }

    // Extract the balance from the response and convert it to float64 format
    balance, err := strconv.ParseFloat(rpcResponse["result"].(map[string]interface{})["balance"].(string), 64)
    if err != nil {
        return 0, err
    }

    return balance / 1000000000000, nil // convert from atomic units to XMR
}

func processQueue(db *sql.DB) error {
	// Retrieve the oldest entry from the queue table
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
			// The queue is empty, so there's nothing to do
			return nil
		}
		return err
	}

	// Check if we can display a new dono
	if displayNewDono(name, amount, currency) {
		// The displayNewDono function is ready to display a new dono,
		// so remove the entry from the queue table
		_, err = db.Exec(`
			DELETE FROM queue WHERE id = ?
		`, id)
		if err != nil {
			return err
		}
	}

	return nil
}


USER TABLE TO CREATE:
PK: UserID
Username
Password
Timezone
ETH Address
SOL Address
HEX Address
XMR Wallet Password (HASHED)
Minimum Dono Threshold
Minimum Media Threshold
Media Enabled
Creation Datetime
Modification Datetime