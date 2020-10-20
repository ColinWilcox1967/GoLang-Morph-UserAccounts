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

func dummyPage(w http.ResponseWriter, r *http.Request){
    fmt.Fprintf(w, "Welcome to the Dummy Page!")
    fmt.Println("Endpoint Hit: dummy Page")
}

func handleRequests() {
    http.HandleFunc("/", dummyPage)
    log.Fatal(http.ListenAndServe(":"+string(httpPort), nil))
}

func handleCommandLineParameters () error {

    var str string
    flag.StringVar (&str, "port", DEFAULT_PORT, "Port on which the user account server will run.")
    flag.StringVar (&logfile, "logfile", DEFAULT_LOG_FILE, "User accounts log file.")
    helpFlag = flag.Bool ("help", false, "Help required by user")
    flag.Parse ()

    // get the port number
    httpPort, err := strconv.Atoi(str)
    fmt.Printf ("Starting server on port %d\n", httpPort)

    return err
}

func showSyntax () {
    simplelogging.LogMessage ("Showing command syntax", simplelogging.LOG_INFO)
    
    fmt.Printf ("UASERVER [-HELP] | [-PORT=<port number>] [LOGFILE=<filepath>]")
        
}

func main() {

    err := handleCommandLineParameters ()

    simplelogging.Init (logfile, false)

    if *helpFlag {
       showSyntax ()
       os.Exit(0) 
    }

   
  
    if err == nil {
        msg := fmt.Sprintf ("Starting user accounts server on port %d,\n", httpPort)
        simplelogging.LogMessage (msg,simplelogging.LOG_INFO)
        handleRequests()
    }
}


