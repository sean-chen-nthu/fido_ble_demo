package models

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// InitDB create tables if not exists
func InitDB() {
	db, err := sql.Open("sqlite3", "../device.db")
	defer db.Close()

	checkErr(err)
	createUsers := `
	CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(64) DEFAULT '',
		display_name VARCHAR(64) DEFAULT '',
		credentials TEXT DEFAULT '',
        created_at DATE NULL,
        updated_at DATE NULL
    );
	`
	_, err = db.Exec(createUsers)
	checkErr(err)

	createCredentials := `
	CREATE TABLE IF NOT EXISTS credentials(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NULL,
        credential TEXT NULL,
        created_at DATE NULL,
        updated_at DATE NULL
    );
	`
	_, err = db.Exec(createCredentials)
	checkErr(err)

}
