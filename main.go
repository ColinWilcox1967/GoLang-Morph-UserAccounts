//
// User Account Server
//
// (c) 2020 Morph Inc.
//

//TO DO : Session token handling

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	//	"github.com/gorilla/securecookie"

	simplelogging "github.com/colinwilcox1967/golangsimplelogging"
	"github.com/gorilla/mux"
)

const (
	DEFAULT_LOG_FILE      string = "LOGFILE.TXT"
	DEFAULT_PORT          string = "8080"
	DEFAULT_ACCOUNTS_FILE string = "USERS.DAT"
	SERVER_VERSION        string = "v0.1"
)

const (
	ACTION_LOGIN               int = 1
	ACTION_LOGOUT              int = 2
	ACTION_ADD_USER_ACCOUNT    int = 3
	ACTION_EDIT_USER_ACCOUNT   int = 4
	ACTION_DELETE_USER_ACCOUNT int = 5
)

type UserAccountRecord struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
	Deleted  bool   `json:"deleted"`
	Blocked  bool   `json:"blocked"`
	Date     string `json:"date"`
}

type ActionResult struct {
	Type    int    `json:"type"`
	Message string `json:"msg"`
	Value   bool   `json:"value"`
	Token   string `json:"token"`
}

// cookie handling
//var cookieHandler = securecookie.New(securecookie.GenerateRandomKey(64),securecookie.GenerateRandomKey(32))

var (
	httpPort     int
	logFile      string
	accountsFile string
	helpFlag     *bool

	userAccounts []UserAccountRecord
)

//
//API Endpoint handler functions
//
func addUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'addUserAccountEndpoint'", simplelogging.LOG_INFO)


//	reqBody, _ := ioutil.ReadAll(r.Body)
	var newAccount UserAccountRecord

	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]


	//json.Unmarshal(reqBody, &newAccount)

	fmt.Printf ("Username : %s, Password : %s\n", username, password)


	// hash the password before writing
	_, newAccount.Password = generateHashFromPassword([]byte(password)) // ?? is this needed?
    newAccount.Username = username

	recordsRead := readUserAccountsFile(accountsFile)

	userAccounts = append(userAccounts, newAccount)

	recordsWritten := writeUserAccountsFile(accountsFile)

	var result ActionResult

	result.Type = ACTION_ADD_USER_ACCOUNT
	result.Token = ""
	if recordsWritten == recordsRead+1 {
		msg := fmt.Sprintf("Added user account %s (username:'%s'\n", newAccount.Id, newAccount.Username)
		simplelogging.LogMessage(msg, simplelogging.LOG_INFO)

		result.Value = true
		result.Message = "New user account created"
	} else {
		result.Value = false
		result.Message = "Failed to add new user account"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAccount)

}

func editUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'editUserAccountEndpoint'", simplelogging.LOG_INFO)

//	vars := mux.Vars(r)
//	username := vars["username"]

//	var accountId int
	recordsRead := readUserAccountsFile(accountsFile)

//	for index, account := range userAccounts {
//		if account.Username == username {
//			accountId = index
//			break
//		}
//	}

	// TO DO Update

	recordsWritten := writeUserAccountsFile(accountsFile)

	var result ActionResult
	result.Type = ACTION_EDIT_USER_ACCOUNT
	result.Token = ""
	if recordsRead == recordsWritten {
		result.Value = true
		result.Message = "User account updated."
	} else {
		result.Value = false
		result.Message = "Failed to update user account."
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func deleteUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'deleteUserAccountEndpoint'", simplelogging.LOG_INFO)

	vars := mux.Vars(r)
	username := vars["username"]

	recordsRead := readUserAccountsFile(accountsFile)

	for index, account := range userAccounts {

		if string(account.Username) == username {
			userAccounts = append(userAccounts[:index], userAccounts[index+1:]...)

			msg := fmt.Sprintf("Removed user account %s (username:'%s'\n", index, account.Username)
			simplelogging.LogMessage(msg, simplelogging.LOG_INFO)
		}
	}
	recordsWritten := writeUserAccountsFile(accountsFile)

	var result ActionResult

	result.Type = ACTION_DELETE_USER_ACCOUNT
	result.Token = ""
	if recordsWritten == recordsRead-1 {
		result.Value = true
		result.Message = "User account deleted"
	} else {
		result.Value = false
		result.Message = "Failed to delete user account"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

}

func findUserAccountByUsername(username string) (bool, int) {

	simplelogging.LogMessage("Hit 'findUserAccountByUsername'", simplelogging.LOG_INFO)

	for index, value := range userAccounts {
		if strings.ToUpper(value.Username) == strings.ToUpper(username) {
			return true, index
		}
	}

	return false, -1 // username not found
}

func loginUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'LoginUserAccountEndpoint'", simplelogging.LOG_INFO)

	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]

	var result ActionResult

	if username != "" && password != "" {
		// load into memory and search for matching username
		_ = readUserAccountsFile(accountsFile)
		foundUser, index := findUserAccountByUsername(username)
		if foundUser {
			actualPasswordFromFile := userAccounts[index].Password
			if comparePasswordAgainstHash(actualPasswordFromFile, password) {
				result = createLoginAttemptResult(true, "Login Successfull")

				//			token := GetSessionToken(r)
				//			setSession(token, r)
			} else {
				result = createLoginAttemptResult(false, "Login Failure - Incorrect Credentials")
			}
		} else {
			result = createLoginAttemptResult(false, "Login Failure - User Not Found")
		}

	} else {
		result = createLoginAttemptResult(false, "Login Failure - No Credentials Supplied")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func createLoginAttemptResult(state bool, msg string) ActionResult {
	var result ActionResult

	result.Type = ACTION_LOGIN
	result.Message = msg
	result.Value = state
	result.Token = ""

	return result
}

func logoutUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'LogoutUserAccountEndpoint'", simplelogging.LOG_INFO)


fmt.Println ("LOGout")
	//	clearSession(r)
}

func handleRequests() {

	gmuxRouter := mux.NewRouter().StrictSlash(true)

	gmuxRouter.HandleFunc("/login/{username}/{password}", loginUserAccountEndpoint)
	gmuxRouter.HandleFunc("/logout", logoutUserAccountEndpoint)
	gmuxRouter.HandleFunc("/add/{username}/{password}", addUserAccountEndpoint)
	gmuxRouter.HandleFunc("/delete/{username}", deleteUserAccountEndpoint)
	gmuxRouter.HandleFunc("/edit/{username}", editUserAccountEndpoint)

	portStr := fmt.Sprintf(":%d", httpPort)

	msg := fmt.Sprintf("Starting user accounts server on port %d\n", httpPort)
	simplelogging.LogMessage(msg, simplelogging.LOG_INFO)

	log.Fatal(http.ListenAndServe(portStr, gmuxRouter))
}

// just simple internalisation
func readUserAccountsFile(accountsFile string) int {

	jsonFile, err := os.Open(accountsFile)

	defer jsonFile.Close()
	if err == nil {
		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &userAccounts)

		return len(userAccounts)

	} else {

		return -1
	}
}

func writeUserAccountsFile(filename string) int {
	file, _ := json.Marshal(userAccounts)

	err := ioutil.WriteFile(filename, file, 0644)
	if err == nil {
		return len(userAccounts)
	}

	return 0

}

func handleCommandLineParameters() (int, error) {

	var str string
	flag.StringVar(&str, "port", DEFAULT_PORT, "Port on which the user account server will run.")
	flag.StringVar(&logFile, "log", DEFAULT_LOG_FILE, "User accounts log file.")
	flag.StringVar(&accountsFile, "file", DEFAULT_ACCOUNTS_FILE, "Specifies the name of the user accounts file.")
	helpFlag = flag.Bool("help", false, "Help required by user.")
	flag.Parse()

	// get the port number
	port, err := strconv.Atoi(str)

	return port, err
}

func showSyntax() {
	simplelogging.LogMessage("Showing command syntax", simplelogging.LOG_INFO)

	fmt.Printf("UASERVER [-HELP] | [-PORT = <port number>] [-FILE = <accounts file path>] [-LOG = <log file path>]\n\n")
	fmt.Println("<port number>        - HTTP port number for server listener. Defaults to 8080.")
	fmt.Println("<accounts file path> - Full or partial path of accounts file. Defaults to USERS.DAT in current folder.\n")
	fmt.Println("<log file path>      - Full or partial path of log file. Defaults to LOGFILE.TXT in current folder.\n")

}

//
// (Hashed) Password Support
//
func generateHashFromPassword(password []byte) (error, string) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		return err, ""
	}

	return nil, string(hash)
}

func comparePasswordAgainstHash(storedHashedPassword, suppliedPlaintextPassword string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(suppliedPlaintextPassword))
	if err != nil {
		return false
	}

	return true
}

//
// Session/Token Support
//
//func setSession (userName string, response http.ResponseWriter) {
//	value := map[string]string{"name": userName,}
//	if encoded, err := cookieHandler.Encode("session", value); err == nil {
//		cookie := &http.Cookie{	Name:  "session",Value: encoded,Path:  "/",}
//		http.SetCookie(response, cookie)
//	}
//}

//func clearSession (response http.ResponseWriter) {
//	cookie := &http.Cookie{Name:   "session",Value:  "",Path:   "/",MaxAge: -1,}
//	http.SetCookie(response, cookie)
//}

//func GetSessionToken(request *http.Request) string {
//	if cookie, err := request.Cookie("session"); err == nil {
//		cookieValue := make(map[string]string)
//		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
//			token = cookieValue["name"]
//		}
//	}
//	return token
//}

func main() {

	var err error
	httpPort, err = handleCommandLineParameters()

	simplelogging.Init(logFile, true)

	if *helpFlag {
		showSyntax()
		os.Exit(0)
	}

	if err == nil {
		fmt.Printf("Starting User Accounts Server %s on Port %d ...\n", SERVER_VERSION, httpPort)
		handleRequests()
	}
}
