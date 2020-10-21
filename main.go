package main

import (
    "fmt"
    "log"
    "net/http"
    "strconv"
    "flag"
    "os"

    simplelogging "github.com/colinwilcox1967/golangsimplelogging"
)

const (
    DEFAULT_LOG_FILE string = "LOGFILE.TXT"
    DEFAULT_PORT string = "8080"
)

var (
    httpPort int
    logfile string
    helpFlag *bool
)

func dummyEndpoint(w http.ResponseWriter, r *http.Request){
    
    simplelogging.LogMessage ("Hit 'dummyEndpoint'", simplelogging.LOG_INFO)
}

func handleRequests() {

   http.HandleFunc("/dummy", dummyEndpoint)

   portStr := fmt.Sprintf (":%d", httpPort)

   msg := fmt.Sprintf ("Starting user accounts server on port %d\n", httpPort)
   simplelogging.LogMessage (msg,simplelogging.LOG_INFO)

   log.Fatal(http.ListenAndServe(portStr, nil))
}

func handleCommandLineParameters () (int, error) {

    var str string
    flag.StringVar (&str, "port", DEFAULT_PORT, "Port on which the user account server will run.")
    flag.StringVar (&logfile, "logfile", DEFAULT_LOG_FILE, "User accounts log file.")
    helpFlag = flag.Bool ("help", false, "Help required by user")
    flag.Parse ()

    // get the port number
    port, err := strconv.Atoi(str)
       
    return port, err
}

func showSyntax () {
    simplelogging.LogMessage ("Showing command syntax", simplelogging.LOG_INFO)
    
    fmt.Printf ("UASERVER [-HELP] | [-PORT = <port number>] [LOGFILE = <filepath>]\n\n")
    fmt.Println ("<port number> - HTTP port number for server listener. Defaults to 8080.")
    fmt.Println ("<filepath>    - Full or partial path of logfile. Defaults to LOGFILE.TXT in current folder.\n")
        
}

func main() {

    var err error
    httpPort, err = handleCommandLineParameters ()

    simplelogging.Init (logfile, false)

    if *helpFlag {
       showSyntax ()
       os.Exit(0) 
    }
  
    if err == nil {
       fmt.Printf ("Starting UAServer on Port %d ...\n", httpPort)
       handleRequests()
    }
}


