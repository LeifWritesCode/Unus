package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	CREATE_STORAGE = `
	CREATE TABLE IF NOT EXISTS secrets (
		id INTEGER NOT NULL PRIMARY KEY,
		data BLOB NOT NULL);`
	INSERT_CRYPTOGRAM = `
	INSERT INTO secrets (id, data) VALUES (?, ?)`
	SELECT_CRYPTOGRAM = `
	SELECT data FROM secrets
	WHERE id = (?)
	LIMIT 1;`
	DELETE_CRYPTOGRAM = `
	DELETE FROM secrets
	WHERE id = (?)`
	DEFAULT_DATABASE = "unus.db"
)

type database struct {
	connection *sql.DB
}

// connects to a database and ensures that the required tables exist
// if they do not exist, creates them
func NewDbConnection(filepath string) *database {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(CREATE_STORAGE)
	if err != nil {
		msg := fmt.Sprintf("%q: %s\n", err, CREATE_STORAGE)
		panic(msg)
	}

	return &database{connection: db}
}

// closes the database connection and disposes of resources
func (db *database) Dispose() {
	db.connection.Close()
}

// selects a cryptogram by id
// returns the blob on success, else an error
func (db *database) SelectCryptogram(id int64) ([]byte, error) {
	rows, err := db.connection.Query(SELECT_CRYPTOGRAM, id)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	defer rows.Close()

	// no secret by this id
	if !rows.Next() {
		msg := "secret not found"
		err := errors.New(msg)
		return nil, err
	}

	var data []byte
	err = rows.Scan(&data)
	if err != nil {
		log.Fatalln("unable to scan row")
		return nil, err
	}

	return data, nil
}

// insert the given cryptogram into the database
// return the index on success, else an error
func (db *database) InsertCryptogram(goflake int64, cryptogram []byte) (int64, error) {
	transaction, err := db.connection.Begin()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	statement, err := transaction.Prepare(INSERT_CRYPTOGRAM)
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}
	defer statement.Close()

	result, err := statement.Exec(goflake, cryptogram)
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	err = transaction.Commit()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	return id, nil
}

// delete the given cryptogram from the database
// return the number of rows affected on success, else an error
func (db *database) DeleteCryptogram(goflake int64) (int64, error) {
	transaction, err := db.connection.Begin()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	statement, err := transaction.Prepare(DELETE_CRYPTOGRAM)
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}
	defer statement.Close()

	result, err := statement.Exec(goflake)
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	err = transaction.Commit()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	rows_affected, err := result.RowsAffected()
	if err != nil {
		log.Fatalln(err)
		return -1, err
	}

	return rows_affected, nil
}
