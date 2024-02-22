package webauthnbluetooth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fido_bluetooth/models"
	"log"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

// FinishRegistrationCredential received from web bluetooth
type FinishRegistrationCredential struct {
	Username string                              `json:"username"`
	Ccr      protocol.CredentialCreationResponse `json:"credential"`
}

// FinishRegistration finish registeration
func FinishRegistration(
	webauthnInstance *webauthn.WebAuthn,
	user models.User,
	session webauthn.SessionData,
	ccr protocol.CredentialCreationResponse,
) (
	*webauthn.Credential,
	error,
) {

	parsedResponse, err := ParseCredentialCreationBluetoothResponse(ccr)
	pcc, _ := json.Marshal(parsedResponse)
	log.Println("register pcc:", string(pcc))
	// d, _ := json.Marshal(parsedResponse)
	// panic(string(d))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	shouldVerifyUser := webauthnInstance.Config.AuthenticatorSelection.UserVerification == protocol.VerificationRequired

	invalidErr := parsedResponse.Verify(session.Challenge, shouldVerifyUser, webauthnInstance.Config.RPID, webauthnInstance.Config.RPOrigin)
	if invalidErr != nil {
		return nil, invalidErr
	}

	return webauthn.MakeNewCredential(parsedResponse)

}

// ParseCredentialCreationBluetoothResponse parse credential
func ParseCredentialCreationBluetoothResponse(ccr protocol.CredentialCreationResponse) (*protocol.ParsedCredentialCreationData, error) {
	// var ccr protocol.CredentialCreationResponse
	// // err := json.NewDecoder(body).Decode(&ccr)
	// err := json.Unmarshal([]byte(credentialJSON), &ccr)

	// if err != nil {
	// 	return nil, protocol.ErrBadRequest.WithDetails("Parse error for Registration").WithInfo(err.Error())
	// }

	if ccr.ID == "" {
		return nil, protocol.ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Missing ID")
	}

	testB64, err := base64.RawURLEncoding.DecodeString(ccr.ID)
	if err != nil || !(len(testB64) > 0) {
		return nil, protocol.ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("ID not base64.RawURLEncoded")
	}

	if ccr.PublicKeyCredential.Credential.Type == "" {
		return nil, protocol.ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Missing type")
	}

	if ccr.PublicKeyCredential.Credential.Type != "public-key" {
		return nil, protocol.ErrBadRequest.WithDetails("Parse error for Registration").WithInfo("Type not public-key")
	}

	var pcc protocol.ParsedCredentialCreationData
	pcc.ID, pcc.RawID, pcc.Type = ccr.ID, ccr.RawID, ccr.Type
	pcc.Raw = ccr

	parsedAttestationResponse, err := ccr.AttestationResponse.Parse()
	if err != nil {
		return nil, protocol.ErrParsingData.WithDetails("Error parsing attestation response")
	}

	pcc.Response = *parsedAttestationResponse

	return &pcc, nil
}
