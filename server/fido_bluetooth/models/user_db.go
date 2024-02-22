package models

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/duo-labs/webauthn/webauthn"
)

// UserDB is user db table
type UserDB struct {
}

// DB return struct UserDB
func DB() *UserDB {
	return &UserDB{}
}

// GetUser return User struct
func (userDB *UserDB) GetUser(username string) (User, error) {
	db, err := sql.Open("sqlite3", "./device.db")
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE user_name=%s", username))
	checkErr(err)

	var user User
	for rows.Next() {
		var id int
		var username string
		var displayName string
		var credentials []webauthn.Credential
		var createdAt time.Time

		err = rows.Scan(&id, &username, &createdAt)
		checkErr(err)
		user = User{
			ID:          id,
			Username:    username,
			DisplayName: displayName,
			credentials: credentials,
			CreatedAt:   createdAt,
		}
	}
	return user, err

	// //更新資料
	// stmt, err = db.Prepare("update userinfo set username=? where uid=?")
	// checkErr(err)

	// res, err = stmt.Exec("astaxieupdate", id)
	// checkErr(err)

	// affect, err := res.RowsAffected()
	// checkErr(err)

	// fmt.Println(affect)

}

// PutUser for create new user
func (userDB *UserDB) PutUser(user User) {
	db, err := sql.Open("sqlite3", "./device.db")
	// prepare insert user
	stmt, err := db.Prepare("INSERT INTO userinfo(username, display_name, created_at) values(?,?,?)")
	checkErr(err)

	now := time.Now().Format("2006-01-02 15:04:05")

	res, err := stmt.Exec(user.Username, user.Username, now)
	checkErr(err)

	id, err := res.LastInsertId()
	checkErr(err)

	fmt.Println(id)
}

// AddCredential associates the credential to the user
func (userDB *UserDB) AddCredential(cred webauthn.Credential) {
	// u.credentials = append(u.credentials, cred)
}
