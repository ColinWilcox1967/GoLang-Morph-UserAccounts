package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	simplelogging "github.com/colinwilcox1967/golangsimplelogging"
	"github.com/gorilla/mux"
)

const (
	DEFAULT_LOG_FILE string = "LOGFILE.TXT"
	DEFAULT_PORT     string = "8080"
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

type Result struct {
	Message string `json:"msg"`
	Value   bool   `json:"value"`
	Token   string `json:"token"`
}

var (
	httpPort int
	logfile  string
	helpFlag *bool

	userAccounts []UserAccountRecord
)

//
//API Endpoint handler functions
//
func addUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'addUserAccountEndpoint'", simplelogging.LOG_INFO)

	reqBody, _ := ioutil.ReadAll(r.Body)
	var newAccount UserAccountRecord

	json.Unmarshal(reqBody, &newAccount)

	userAccounts = append(userAccounts, newAccount)

	json.NewEncoder(w).Encode(newAccount)
}

func deleteUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'deleteUserAccountEndpoint'", simplelogging.LOG_INFO)

	vars := mux.Vars(r)
	id := vars["id"]

	for index, account := range userAccounts {

		if string(account.Id) == id {
			userAccounts = append(userAccounts[:index], userAccounts[index+1:]...)
		}
	}

}

func findUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {

	simplelogging.LogMessage("Hit 'findUserAccountEndpoint'", simplelogging.LOG_INFO)

	//    vars := mux.Vars(r)
	//    id := vars["id"]

}

func dummyPageEndpoint(w http.ResponseWriter, r *http.Request) {
}

func loginUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'LoginUserAccountEndpoint'", simplelogging.LOG_INFO)

	fmt.Println("login")
	vars := mux.Vars(r)
	username := vars["username"]
	password := vars["password"]

	var result Result
	result.Token = "random token"
	result.Message = "Login Successful"
	result.Value = true

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func logoutUserAccountEndpoint(w http.ResponseWriter, r *http.Request) {
	simplelogging.LogMessage("Hit 'LogoutUserAccountEndpoint'", simplelogging.LOG_INFO)

}

func handleRequests() {

	gmuxRouter := mux.NewRouter().StrictSlash(true)

	gmuxRouter.HandleFunc("/login/{username}/{password}", loginUserAccountEndpoint)
	gmuxRouter.HandleFunc("/logout", logoutUserAccountEndpoint).Methods("POST")
	gmuxRouter.HandleFunc("/add", addUserAccountEndpoint).Methods("POST")
	gmuxRouter.HandleFunc("/delete", deleteUserAccountEndpoint).Methods("DELETE")
	gmuxRouter.HandleFunc("/find", findUserAccountEndpoint).Methods("GET")

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

func writeAllUserAccounts() {

}

func handleCommandLineParameters() (int, error) {

	var str string
	flag.StringVar(&str, "port", DEFAULT_PORT, "Port on which the user account server will run.")
	flag.StringVar(&logfile, "logfile", DEFAULT_LOG_FILE, "User accounts log file.")
	helpFlag = flag.Bool("help", false, "Help required by user.")
	flag.Parse()

	// get the port number
	port, err := strconv.Atoi(str)

	return port, err
}

func showSyntax() {
	simplelogging.LogMessage("Showing command syntax", simplelogging.LOG_INFO)

	fmt.Printf("UASERVER [-HELP] | [-PORT = <port number>] [LOGFILE = <filepath>]\n\n")
	fmt.Println("<port number> - HTTP port number for server listener. Defaults to 8080.")
	fmt.Println("<filepath>    - Full or partial path of logfile. Defaults to LOGFILE.TXT in current folder.\n")

}

func main() {

	var err error
	httpPort, err = handleCommandLineParameters()

	simplelogging.Init(logfile, false)

	if *helpFlag {
		showSyntax()
		os.Exit(0)
	}

	if err == nil {
		fmt.Printf("Starting UAServer on Port %d ...\n", httpPort)
		handleRequests()
	}
}
