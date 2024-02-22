package service

import (
	"strconv"
	"strings"

	// "database/sql"
	"encoding/json"
	"fmt"
	"log"

	"fido_bluetooth/models"
	"fido_bluetooth/service/webauthnbluetooth"

	// "github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"

	// _ "github.com/mattn/go-sqlite3"
	"github.com/paypal/gatt"
)

var webauthnInstance *webauthn.WebAuthn
var err error

// var sessionStore *session.Store

// NewWebauthnService is create a webauthn service for the device
func NewWebauthnService() *gatt.Service {
	// db, err := sql.Open("sqlite3", "../device.db")
	// checkErr(err)
	// defer db.Close()
	var registerSessionData webauthn.SessionData
	var loginSessionData webauthn.SessionData

	var registerChallengeIndex = 0
	var loginChallengeIndex = 0
	var index = 0
	var registerChallengeSlice []string
	var loginChallengeSlice []string
	var challenge string
	var packageNum int
	var maxLen = 250
	isSuccess := false

	var receivedCredential []string

	webauthnInstance, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "IoT Device", // Display Name for your site
		RPID:          "localhost",  // Generally the domain name for your site
		// RPID:     "09fc95c0-c111-11e3-9904-0002a5d5c51b", // Generally the domain name for your site
		RPOrigin: "http://localhost:8080", // The origin URL for WebAuthn requests
		// RPOrigin: "09fc95c0-c111-11e3-9904-0002a5d5c51b", // The origin URL for WebAuthn requests
		// RPIcon:        "https://duo.com/logo.png",             // Optional icon URL for your site
	})
	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	models.InitDB()

	// sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}
	s := gatt.NewService(gatt.MustParseUUID("09fc95c0-c111-11e3-9904-0002a5d5c51b"))

	// var opt map[string]interface{}
	// opt := map[string]string{
	// 	"loginBegin":     "11fac9e1-c111-11e3-9246-0002a5d5c51b",
	// 	"registerBegin":  "11fac9e2-c111-11e3-9246-0002a5d5c51b",
	// 	"loginFinish":    "11fac9e3-c111-11e3-9246-0002a5d5c51b",
	// 	"registerFinish": "11fac9e4-c111-11e3-9246-0002a5d5c51b",
	// }
	// optJSON, err := json.Marshal(opt)

	// // discover characteristic
	// optCharacteristic := s.AddCharacteristic(gatt.MustParseUUID("11fac9e0-c111-11e3-9246-0002a5d5c51b"))
	// if err == nil {
	// 	optCharacteristic.SetValue(optJSON)
	// }
	// optCharacteristic.HandleReadFunc(
	// 	func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
	// 		charValue := optCharacteristic.GetValue()
	// 		fmt.Fprintf(rsp, string(charValue))
	// 	})

	// register begin
	registerBeginCharacteristic := s.AddCharacteristic(gatt.MustParseUUID("11fac9e2-c111-11e3-9246-0002a5d5c51b"))

	registerBeginCharacteristic.HandleWriteFunc(
		// create challenge and write to value
		func(r gatt.Request, data []byte) (status byte) {
			username := string(data)
			// get user
			user, err := models.GetUser(username)
			// user doesn't exist, create new user
			log.Println(user)
			if err != nil {
				user = models.NewUser(username)
			}

			registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
				credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
			}

			// generate PublicKeyCredentialCreationOptions, session data
			options, registerSessionDataTemp, err := webauthnInstance.BeginRegistration(
				user,
				registerOptions,
			)

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			// store session and challenge data
			registerSessionData = *registerSessionDataTemp
			value, err := json.Marshal(options)
			challenge = string(value)

			// put challenge into package
			challengeLength := len(challenge)
			if 0 == challengeLength%maxLen {
				packageNum = challengeLength / maxLen
			} else {
				packageNum = challengeLength/maxLen + 1
			}
			for i := 0; i < packageNum; i++ {
				isLastOne := packageNum-1 == i
				if isLastOne {
					registerChallengeSlice = append(registerChallengeSlice, challenge[i*maxLen:])
					registerChallengeSlice = append(registerChallengeSlice, "END")
					break
				}
				registerChallengeSlice = append(registerChallengeSlice, challenge[i*maxLen:(i+1)*maxLen])
			}

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			return gatt.StatusSuccess
		})

	registerBeginCharacteristic.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			if 0 == len(registerChallengeSlice) {
				fmt.Fprintf(rsp, strconv.FormatBool(false))
				return
			}

			res := registerChallengeSlice[registerChallengeIndex]

			registerChallengeIndex++
			isLastOne := registerChallengeIndex == len(registerChallengeSlice)
			if isLastOne {
				registerChallengeIndex = 0
				registerChallengeSlice = nil
			}

			fmt.Fprintf(rsp, res)
		})

	// register finish
	registerFinishCharacteristic := s.AddCharacteristic(gatt.MustParseUUID("11fac9e4-c111-11e3-9246-0002a5d5c51b"))

	registerFinishCharacteristic.HandleWriteFunc(
		// get credential
		func(r gatt.Request, data []byte) (status byte) {

			if string(data) == "END" {
				// last package
				index = 0
				log.Println("register finish:", "END")
			} else {
				receivedCredential = append(receivedCredential, string(data))
				log.Println("register finish:", strconv.Itoa(index))
				index++
				return gatt.StatusSuccess
			}

			receivedCredentialJSON := strings.Join(receivedCredential, "")
			receivedCredential = nil

			var finishRegistrationCredential webauthnbluetooth.FinishRegistrationCredential

			// decode data into FinishRegistrationCredential
			err := json.Unmarshal([]byte(receivedCredentialJSON), &finishRegistrationCredential)
			log.Println("register finish:", receivedCredentialJSON)
			checkErr(err)
			if err != nil {
				return gatt.StatusUnexpectedError
			}

			username := finishRegistrationCredential.Username
			ccr := finishRegistrationCredential.Ccr
			// get user
			user, err := models.GetUser(username)
			// user not exist
			checkErr(err)
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			// parse ccr(CredentialCreationResponse) into credential
			credential, err := webauthnbluetooth.FinishRegistration(webauthnInstance, *user, registerSessionData, ccr)
			checkErr(err)
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			// add credential to user
			user.AddCredential(*credential)

			// update to db
			user.Update()
			isSuccess = true
			return gatt.StatusSuccess
		})

	registerFinishCharacteristic.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {

			fmt.Fprintf(rsp, strconv.FormatBool(isSuccess))
			isSuccess = false
		})

	// login begin
	loginBeginCharacteristic := s.AddCharacteristic(gatt.MustParseUUID("11fac9e1-c111-11e3-9246-0002a5d5c51b"))

	loginBeginCharacteristic.HandleWriteFunc(
		// create and response challenge
		func(r gatt.Request, data []byte) (status byte) {
			username := string(data)

			// get user
			user, err := models.GetUser(username)

			// user doesn't exist
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			// generate PublicKeyCredentialRequestOptions, session data
			options, loginSessionDataTemp, err := webauthnInstance.BeginLogin(user)
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			loginSessionData = *loginSessionDataTemp

			value, err := json.Marshal(options)

			challenge = string(value)

			// put challenge into package
			challengeLength := len(challenge)
			if 0 == challengeLength%maxLen {
				packageNum = challengeLength / maxLen
			} else {
				packageNum = challengeLength/maxLen + 1
			}
			for i := 0; i < packageNum; i++ {
				isLastOne := packageNum-1 == i
				if isLastOne {
					loginChallengeSlice = append(loginChallengeSlice, challenge[i*maxLen:])
					loginChallengeSlice = append(loginChallengeSlice, "END")
					break
				}
				loginChallengeSlice = append(loginChallengeSlice, challenge[i*maxLen:(i+1)*maxLen])
			}

			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			return gatt.StatusSuccess
		})

	loginBeginCharacteristic.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {

			if 0 == len(loginChallengeSlice) {
				fmt.Fprintf(rsp, strconv.FormatBool(false))
				return
			}
			res := loginChallengeSlice[loginChallengeIndex]

			loginChallengeIndex++

			isLastOne := loginChallengeIndex == len(loginChallengeSlice)
			if isLastOne {
				loginChallengeIndex = 0
				loginChallengeSlice = nil
			}

			fmt.Fprintf(rsp, res)
		})

	// login finish
	loginFinishCharacteristic := s.AddCharacteristic(gatt.MustParseUUID("11fac9e3-c111-11e3-9246-0002a5d5c51b"))

	loginFinishCharacteristic.HandleWriteFunc(
		// get assertion
		func(r gatt.Request, data []byte) (status byte) {
			if string(data) == "END" {
				// last package
				index = 0
				log.Println("login finish:", "END")
			} else {
				receivedCredential = append(receivedCredential, string(data))
				log.Println("login finish:", strconv.Itoa(index))
				index++
				return gatt.StatusSuccess
			}

			receivedCredentialJSON := strings.Join(receivedCredential, "")
			receivedCredential = nil

			var finishLoginCredential webauthnbluetooth.FinishLoginCredential

			// decode data into FinishLoginCredential
			err := json.Unmarshal([]byte(receivedCredentialJSON), &finishLoginCredential)
			log.Println("login finish:", receivedCredentialJSON)
			checkErr(err)
			if err != nil {
				return gatt.StatusUnexpectedError
			}

			username := finishLoginCredential.Username
			car := finishLoginCredential.Car

			// get user
			user, err := models.GetUser(username)

			// user doesn't exist
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			// check car and parse car(CredentialAssertionResponse) into credential
			_, err = webauthnbluetooth.FinishLogin(webauthnInstance, *user, loginSessionData, car)
			if err != nil {
				log.Println(err)
				return gatt.StatusUnexpectedError
			}

			isSuccess = true
			return gatt.StatusSuccess
		})

	loginFinishCharacteristic.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {

			fmt.Fprintf(rsp, strconv.FormatBool(isSuccess))
			isSuccess = false
		})

	return s
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
