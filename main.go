//
// User Account Server
//
// (c) 2020 Morph Inc.
//

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	Id       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
	Deleted  bool   `json:"deleted"`
	Blocked  bool   `json:"blocked"`
	Date     string `json:"date"`
}

// Assorted structures for mapping body content
type ActionResult struct {
	Type    int    `json:"type"`
	Message string `json:"msg"`
	Token   string `json:"token"`
	Code    int    `json:"code"`
}

type ChangeAccountPasswordMessage struct {
	Username    string `json:"username"`
	OldPassword string `json:"oldpassword"`
	NewPassword string `json:"newpassword"`
}

type LoginAccountMessage struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DeleteAccountMessage struct {
	Username string `json:"username"`
}

type EditAccountMessage struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type RegisterAccountMessage struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type LogoutAccountMessage struct {
	Username string `json:"username"`
}

var (
	httpPort     int
	logFile      string
	accountsFile string
	helpFlag     *bool

	userAccounts []UserAccountRecord
)

//
// API Endpoint handler functions
//

// ReqBody Format: {"username":xxxx, "oldpassword":xxxx, "newpassword":xxxx}

func ChangeUserAccountPasswordEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'ChangeUserAccountPasswordEndpoint'", simplelogging.LOG_INFO)

	var result ActionResult

	reqBody, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if err == nil {
		// look for 'username', 'oldpassword' and 'newpassword' tags

		var message ChangeAccountPasswordMessage

		err := json.Unmarshal(reqBody, &message)
		if err == nil {
			// check if account exists and password matches before updating
			exists, index := findUserAccountByUsername(message.Username)
			if exists {
				if comparePasswordAgainstHash(userAccounts[index].Password, message.OldPassword) {

					_, hashedNewPassword := generateHashFromPassword([]byte(message.NewPassword))

					userAccounts[index].Password = hashedNewPassword
					result.Code = http.StatusOK
					result.Message = "Password changed"
				} else {
					result.Code = http.StatusBadRequest
					result.Message = "Invalid credentials"
				}
			} else {
				result.Code = http.StatusNotFound
				result.Message = "Account not found"
			}
		}

	} else {
		result.Code = http.StatusBadRequest
		result.Message = "Bad Request Bodty Contents"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

}

func RegisterUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'RegisterUserAccountEndpoint'", simplelogging.LOG_INFO)

	//	reqBody, _ := ioutil.ReadAll(r.Body)

	var newAccount UserAccountRecord
	var result ActionResult

	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]

	exists, _ := findUserAccountByUsername(username)

	if !exists {
		//json.Unmarshal(reqBody, &newAccount)

		// hash the password before writing
		_, newAccount.Password = generateHashFromPassword([]byte(password)) // ?? is this needed?
		newAccount.Username = username

		recordsRead := readUserAccountsFile(accountsFile)

		userAccounts = append(userAccounts, newAccount)

		recordsWritten := writeUserAccountsFile(accountsFile)

		result.Type = ACTION_ADD_USER_ACCOUNT
		result.Token = ""
		if recordsWritten == recordsRead+1 {
			msg := fmt.Sprintf("Added user account %s (username:'%s'\n", newAccount.Id, newAccount.Username)
			simplelogging.LogMessage(msg, simplelogging.LOG_INFO)

			result.Code = http.StatusCreated
			result.Message = "New user account created"
		} else {
			result.Code = http.StatusNotFound
			result.Message = "Failed to add new user account"
		}
	} else {
		result.Code = http.StatusBadRequest
		result.Message = "Account already exists"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

}

func editUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'editUserAccountEndpoint'", simplelogging.LOG_INFO)

	vars := mux.Vars(r)
	username := vars["username"]

	var accountIndex int = -1
	recordsRead := readUserAccountsFile(accountsFile)

	for index, account := range userAccounts {
		if account.Username == username {
			accountIndex = index
			break
		}
	}

	if accountIndex >= 0 {

		// Header decoder and reject any unknownm fields
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		// TO DO Update

		recordsWritten := writeUserAccountsFile(accountsFile)

		var result ActionResult
		result.Type = ACTION_EDIT_USER_ACCOUNT
		result.Token = ""
		if recordsRead == recordsWritten {
			result.Code = http.StatusOK
			result.Message = "User account updated."
		} else {
			result.Code = http.StatusBadRequest
			result.Message = "Failed to update user account."
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func deleteUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'deleteUserAccountEndpoint'", simplelogging.LOG_INFO)

	var foundRecord bool

	vars := mux.Vars(r)
	username := vars["username"]

	recordsRead := readUserAccountsFile(accountsFile)

	for index, account := range userAccounts {

		if string(account.Username) == username {
			userAccounts = append(userAccounts[:index], userAccounts[index+1:]...)
			foundRecord = true

			msg := fmt.Sprintf("Removed user account %s (username:'%s')\n", index, account.Username)
			simplelogging.LogMessage(msg, simplelogging.LOG_INFO)
		}
	}

	var result ActionResult

	if !foundRecord {
		msg := fmt.Sprintf("Unable to find user account tieh name ('%s')\n", username)
		simplelogging.LogMessage(msg, simplelogging.LOG_INFO)

		result.Code = http.StatusNotFound
		result.Message = "Account not found"

	} else {

		recordsWritten := writeUserAccountsFile(accountsFile)

		result.Type = ACTION_DELETE_USER_ACCOUNT
		result.Token = ""
		if recordsWritten == recordsRead-1 {
			result.Code = http.StatusOK
			result.Message = "User account deleted"
		} else {
			result.Code = http.StatusBadRequest
			result.Message = "Failed to delete user account"
		}

	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func loginUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'LoginUserAccountEndpoint'", simplelogging.LOG_INFO)

	//	vars := mux.Vars(r)
	//	username := vars["username"]
	//	password := vars["password"]

	var message LoginAccountMessage
	var result ActionResult

	reqBody, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	json.Unmarshal(reqBody, &message)

	if message.Username != "" && message.Password != "" {
		// load into memory and search for matching username
		_ = readUserAccountsFile(accountsFile)
		foundUser, index := findUserAccountByUsername(message.Username)
		if foundUser {
			actualPasswordFromFile := userAccounts[index].Password
			if comparePasswordAgainstHash(actualPasswordFromFile, message.Password) {

				err, token := GenerateNewSessionToken()
				if err == nil {
					result = createLoginAttemptResult(http.StatusOK, "Login Successfull")
					result.Token = token
				} else {
					result = createLoginAttemptResult(http.StatusUnauthorized, "Unable To Create Session Token")
				}
			} else {
				result = createLoginAttemptResult(http.StatusBadRequest, "Login Failure - Incorrect Credentials")
			}
		} else {
			result = createLoginAttemptResult(http.StatusNotFound, "Login Failure - User Not Found")
		}

	} else {
		result = createLoginAttemptResult(http.StatusNoContent, "Login Failure - No Credentials Supplied")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func createLoginAttemptResult(code int, msg string) ActionResult {
	var result ActionResult

	result.Type = ACTION_LOGIN
	result.Message = msg
	result.Code = code
	result.Token = ""

	return result
}

func logoutUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'LogoutUserAccountEndpoint'", simplelogging.LOG_INFO)

	var result ActionResult

	result.Type = ACTION_LOGOUT
	result.Token = ""
	result.Message = "Success"
	result.Code = http.StatusOK

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleRequests() {

	gmuxRouter := mux.NewRouter().StrictSlash(true)

	gmuxRouter.HandleFunc("/login/{username}/{password}", loginUserAccountEndpoint)
	gmuxRouter.HandleFunc("/logout", logoutUserAccountEndpoint)
	gmuxRouter.HandleFunc("/register/{username}/{password}", RegisterUserAccountEndpoint)
	gmuxRouter.HandleFunc("/delete/{username}", deleteUserAccountEndpoint)
	gmuxRouter.HandleFunc("/edit/{username}", editUserAccountEndpoint)
	gmuxRouter.HandleFunc("/changepassword", ChangeUserAccountPasswordEndpoint)

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

func findUserAccountByUsername(username string) (bool, int) {

	simplelogging.LogMessage("Hit 'findUserAccountByUsername'", simplelogging.LOG_INFO)

	for index, value := range userAccounts {
		if strings.ToUpper(value.Username) == strings.ToUpper(username) {
			return true, index
		}
	}

	return false, -1 // username not found
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
// Session Token Support
//
func GenerateNewSessionToken() (error, string) {
	uuid, err := uuid.NewV4()
	if err == nil {
		return nil, uuid.String()
	}

	return err, ""
}

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
