package models

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	_ "github.com/mattn/go-sqlite3"
)

// User for DB
type User struct {
	ID          int
	Username    string
	DisplayName string
	credentials []webauthn.Credential
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewUser for create a new user
func NewUser(username string) *User {
	db, err := sql.Open("sqlite3", "../device.db")
	defer db.Close()

	user := User{
		Username:    username,
		DisplayName: username,
	}

	// prepare insert user
	stmt, err := db.Prepare("INSERT INTO users(username, display_name, created_at, updated_at) values(?,?,?,?)")
	checkErr(err)

	now := time.Now().Format("2006-01-02 15:04:05")

	res, err := stmt.Exec(user.Username, user.Username, now, now)
	checkErr(err)

	id, err := res.LastInsertId()
	user.ID = int(id)
	checkErr(err)

	return &user
}

// GetUser return User struct
func GetUser(usernameSearch string) (*User, error) {
	db, err := sql.Open("sqlite3", "../device.db")
	defer db.Close()

	rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE username='%s'", usernameSearch))
	// rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%d", 1))

	if err != nil {
		return nil, err
	}
	// checkErr(err)

	var user User
	if rows.Next() {
		var id int
		var username string
		var displayName string
		var credentialJSON string
		var credentials []webauthn.Credential
		var createdAt time.Time
		var updatedAt time.Time

		err = rows.Scan(&id, &username, &displayName, &credentialJSON, &createdAt, &updatedAt)
		// checkErr(err)
		if "" != credentialJSON {
			err = json.Unmarshal([]byte(credentialJSON), &credentials)
		}
		checkErr(err)

		user = User{
			ID:          id,
			Username:    username,
			DisplayName: displayName,
			credentials: credentials,
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		}
		// value, _ := json.Marshal(user)
		// panic(string(value))
		rows.Close()
		return &user, nil
	}
	rows.Close()
	err = errors.New("no such user")

	return nil, err

}

// Update for updating user
func (user *User) Update() {
	db, err := sql.Open("sqlite3", "../device.db")
	defer db.Close()

	//更新資料
	// id
	// username
	// display_name
	// updated_at
	// credentials
	stmt, err := db.Prepare(`
		UPDATE users SET
		username=?,
		display_name=?,
		credentials=?,
		updated_at=?
		WHERE id=?
	`)
	checkErr(err)

	credentialsJSON, err := json.Marshal(user.credentials)

	res, err := stmt.Exec(user.Username, user.DisplayName, string(credentialsJSON), time.Now().Format("2006-01-02 15:04:05"), user.ID)
	checkErr(err)

	affect, err := res.RowsAffected()
	checkErr(err)

	log.Println("Update:", strconv.Itoa(int(affect)))
	fmt.Println(affect)
}

// AddCredential associates the credential to the user
func (user *User) AddCredential(cred webauthn.Credential) {
	user.credentials = append(user.credentials, cred)
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (user User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range user.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

// WebAuthnID returns the user's ID
func (user User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(user.ID))
	return buf
}

// WebAuthnName returns the user's username
func (user User) WebAuthnName() string {
	return user.Username
}

// WebAuthnDisplayName returns the user's display name
func (user User) WebAuthnDisplayName() string {
	return user.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (user User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns credentials owned by the user
func (user User) WebAuthnCredentials() []webauthn.Credential {
	return user.credentials
}

// // PutUser for create new user
// func (u User) PutUser(user User) {
// 	db, err := sql.Open("sqlite3", "../device.db")
// 	// prepare insert user
// 	stmt, err := db.Prepare("INSERT INTO userinfo(username, display_name, created_at) values(?,?,?)")
// 	checkErr(err)

// 	now := time.Now().Format("2006-01-02 15:04:05")

// 	res, err := stmt.Exec(user.Username, user.Username, now)
// 	checkErr(err)

// 	id, err := res.LastInsertId()
// 	checkErr(err)

// 	fmt.Println(id)
// }

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
