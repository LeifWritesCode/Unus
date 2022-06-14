package unus

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	ecies "code.leif.uk/lwg/unus/pkg/go-ecies"
	"github.com/tjarratt/babble"
)

type secret struct {
	ContentType string
	Secret      []byte
}

// decodes a secret push request
func decode_secret_request(w http.ResponseWriter, r *http.Request) (*secret, error) {
	// enforce content-type header
	content_type := r.Header.Get("Content-Type")
	switch content_type {
	case MIME_STRING:
	case MIME_PNG:
	case MIME_JPEG:
	case MIME_JSON:
		break
	default:
		msg := "content-type header is not supported type"
		err := errors.New(msg)
		http.Error(w, msg, http.StatusUnsupportedMediaType)
		return nil, err
	}

	// enforce 1 MiB max.
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// enforce no unknown fields
	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// may need to do some additional validation on the content
		// for now, don't bother
		msg := "an unknown error occurred during read"
		err := errors.New(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}

	return &secret{ContentType: content_type, Secret: content}, nil
}

func generate_passphrase() string {
	babbler := babble.NewBabbler()
	babbler.Count = 4
	babbler.Separator = "-"
	return babbler.Babble()
}

// creates a new secret and returns the id + key
func newSecretHandler(w http.ResponseWriter, r *http.Request) {
	secret, err := decode_secret_request(w, r)
	if err != nil {
		msg := "nothing received"
		http.Error(w, msg, http.StatusBadRequest)
		log.Println(err)
		return
	}

	// marshal the secret as json bytes
	json_bytes, err := json.Marshal(secret)
	if err != nil {
		msg := "error encoding payload"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// create the passphrase and key
	passphrase := generate_passphrase()
	receiver_key, err := ecies.NewECPrivateKeyFromBytes([]byte(passphrase))
	if err != nil {
		msg := "error deciding passphrase"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// then encrypt it
	cryptogram, err := ecies.EncryptEphemeral(receiver_key.PublicKey(), json_bytes)
	if err != nil {
		msg := "error encoding cryptogram"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// store the cryptogram and get the id number back
	id, err := database.InsertCryptogram(goflake.Next(), cryptogram)
	if err != nil {
		msg := "error storing cryptogram"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// crete and marshal the response
	response_bytes, err := json.Marshal(responseBody{Id: id, Passphrase: passphrase})
	if err != nil {
		msg := "error encoding response"
		http.Error(w, msg, http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// then return the id and password to the user
	writeResponseBytes(w, MIME_JSON, response_bytes)
}
