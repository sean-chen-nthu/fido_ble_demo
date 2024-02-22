package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()

	// r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	// r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	// r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	// r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")
	// r.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
	// 	jsonResponse(w, "test", http.StatusOK)
	// }).Methods("GET")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))

	serverAddress := ":8080"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}
