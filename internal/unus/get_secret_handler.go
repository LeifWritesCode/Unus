package unus

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	ecies "code.leif.uk/lwg/unus/pkg/go-ecies"
)

// gets an existing secret
func getSecretHandler(w http.ResponseWriter, r *http.Request) {
	matches := secret_id_regex.FindStringSubmatch(r.URL.Path)
	if len(matches) != 2 {
		msg := "too many ids received"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println(msg)
		return
	}

	// first match is the entire path, second is our id
	secret_id, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		msg := "badly-formed secret id"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println(err)
		return
	}

	// look for the passphrase in the headers
	matches = basic_auth_regex.FindStringSubmatch(r.Header.Get("Authorization"))
	if len(matches) != 2 {
		msg := "no passphrase given"
		http.Error(w, msg, http.StatusUnauthorized)
		log.Println(err)
		return
	}

	// http basic auth encodes as base64
	passphrase_bytes, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		msg := "poorly formed passphrase"
		http.Error(w, msg, http.StatusUnauthorized)
		log.Println(err)
		return
	}

	// if the basic auth is properly formed, it contains a colon
	// trim everything up to and including the colon
	offset := strings.Index(string(passphrase_bytes), ":") + 1
	passphrase := string(passphrase_bytes[offset:])

	cryptogram, err := database.SelectCryptogram(secret_id)
	if err != nil {
		msg := "error finding cryptogram"
		http.Error(w, msg, http.StatusNotFound)
		log.Println(err)
		return
	}

	// create the key from the passphrase we were given
	receiver_key, err := ecies.NewECPrivateKeyFromBytes([]byte(passphrase))
	if err != nil {
		msg := "error deciding passphrase"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	payload, err := ecies.Decrypt(receiver_key, cryptogram)
	if err != nil {
		msg := "error during decryption"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	var secret secret
	if err := json.Unmarshal(payload, &secret); err != nil {
		msg := "error decoding payload"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	_, err = database.DeleteCryptogram(secret_id)
	if err != nil {
		msg := "error deleting cryptogram"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	writeResponseBytes(w, secret.ContentType, secret.Secret)
}
