package webauthnbluetooth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fido_bluetooth/models"
	"fmt"
	"log"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

// FinishLoginCredential received from web bluetooth
type FinishLoginCredential struct {
	Username string                               `json:"username"`
	Car      protocol.CredentialAssertionResponse `json:"assertion"`
}

// FinishLogin : Take the response from the client and validate it against the user credentials and stored session data
func FinishLogin(
	webauthnInstance *webauthn.WebAuthn,
	user models.User,
	session webauthn.SessionData,
	car protocol.CredentialAssertionResponse,
) (
	*webauthn.Credential,
	error,
) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	parsedResponse, err := ParseCredentialRequestBluetoothResponse(car)
	par, _ := json.Marshal(parsedResponse)
	log.Println("login par:", string(par))

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	userCredentials := user.WebAuthnCredentials()
	var credentialFound bool
	if len(session.AllowedCredentialIDs) > 0 {
		var credentialsOwned bool
		for _, userCredential := range userCredentials {
			for _, allowedCredentialID := range session.AllowedCredentialIDs {
				if bytes.Equal(userCredential.ID, allowedCredentialID) {
					credentialsOwned = true
					break
				}
				credentialsOwned = false
			}
		}
		if !credentialsOwned {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowedCredentialList")
		}
		for _, allowedCredentialID := range session.AllowedCredentialIDs {
			if bytes.Equal(parsedResponse.RawID, allowedCredentialID) {
				credentialFound = true
				break
			}
		}
		if !credentialFound {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own the credential returned")
		}
	}

	// Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
	// the owner of the public key credential identified by credential.id.

	// This is in part handled by our Step 1

	userHandle := parsedResponse.Response.UserHandle
	if userHandle != nil && len(userHandle) > 0 {
		if !bytes.Equal(userHandle, user.WebAuthnID()) {
			return nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
		}
	}

	// Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
	// for your use case), look up the corresponding credential public key.
	var loginCredential webauthn.Credential
	for _, cred := range userCredentials {
		if bytes.Equal(cred.ID, parsedResponse.RawID) {
			loginCredential = cred
			credentialFound = true
			break
		}
		credentialFound = false
	}

	if !credentialFound {
		return nil, protocol.ErrBadRequest.WithDetails("Unable to find the credential for the returned credential ID")
	}

	shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

	rpID := webauthnInstance.Config.RPID
	rpOrigin := webauthnInstance.Config.RPOrigin

	// Handle steps 4 through 16
	validError := parsedResponse.Verify(session.Challenge, rpID, rpOrigin, shouldVerifyUser, loginCredential.PublicKey)
	if validError != nil {
		return nil, validError
	}

	// Handle step 17
	loginCredential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)

	return &loginCredential, nil
}

// ParseCredentialRequestBluetoothResponse to
func ParseCredentialRequestBluetoothResponse(car protocol.CredentialAssertionResponse) (*protocol.ParsedCredentialAssertionData, error) {
	// var car protocol.CredentialAssertionResponse
	// err := json.NewDecoder(body).Decode(&car)
	// if err != nil {
	// 	return nil, ErrBadRequest.WithDetails("Parse error for Assertion")
	// }

	if car.ID == "" {
		return nil, protocol.ErrBadRequest.WithDetails("CredentialAssertionResponse with ID missing")
	}

	_, err := base64.RawURLEncoding.DecodeString(car.ID)
	if err != nil {
		return nil, protocol.ErrBadRequest.WithDetails("CredentialAssertionResponse with ID not base64url encoded")
	}
	if car.Type != "public-key" {
		return nil, protocol.ErrBadRequest.WithDetails("CredentialAssertionResponse with bad type")
	}
	var par protocol.ParsedCredentialAssertionData
	par.ID, par.RawID, par.Type = car.ID, car.RawID, car.Type
	par.Raw = car

	par.Response.Signature = car.AssertionResponse.Signature
	par.Response.UserHandle = car.AssertionResponse.UserHandle

	// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// We don't call it cData but this is Step 5 in the spec.
	err = json.Unmarshal(car.AssertionResponse.ClientDataJSON, &par.Response.CollectedClientData)
	if err != nil {
		return nil, err
	}

	err = par.Response.AuthenticatorData.Unmarshal(car.AssertionResponse.AuthenticatorData)
	if err != nil {
		return nil, protocol.ErrParsingData.WithDetails("Error unmarshalling auth data")
	}
	return &par, nil
}
