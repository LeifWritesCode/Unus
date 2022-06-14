package unus

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"code.leif.uk/lwg/unus/internal/unus/db"
)

const (
	MIME_JSON   = "application/json"
	MIME_STRING = "text/plain"
	MIME_PNG    = "image/png"
	MIME_JPEG   = "image/jpeg"
)

var (
	secret_id_regex  = regexp.MustCompile(`^/api/v1/secrets/(?P<id>\d{1,19})$`)
	basic_auth_regex = regexp.MustCompile(`^Basic (?P<passphrase>[\w+\/=]+)$`)
	database         = db.NewDbConnection(db.DEFAULT_DATABASE)
)

type responseBody struct {
	Id         int64
	Passphrase string
}

// writes a response to the given writer
func writeResponseBytes(w http.ResponseWriter, contentType string, response []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(http.StatusOK)
	reader := bytes.NewReader(response)
	io.Copy(w, reader)
}

// writes a method not allowed message to the response stream
func notAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// returns true if the request method is included in acceptedMethods
// otherwise, returns false and the caller should not use the response.
func isMethodAllowed(w http.ResponseWriter, r *http.Request, allowedMethods []string) bool {
	found := false
	for _, method := range allowedMethods {
		if r.Method == method {
			found = true
		}
	}
	return found
}

// wraps a request handler with generic error checking code, returning the result
func createHandler(fn func(http.ResponseWriter, *http.Request), allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		if !isMethodAllowed(w, r, allowedMethods) {
			notAllowed(w)
			return
		}

		fn(w, r)
	}
}

// serves unus
func Serve(listenAddress string) error {
	defer goflake.Dispose()
	defer database.Dispose()

	http.HandleFunc("/", createHandler(frontPageHandler, []string{"GET"}))
	http.HandleFunc("/api/v1/secrets", createHandler(newSecretHandler, []string{"POST"}))
	http.HandleFunc("/api/v1/secrets/", createHandler(getSecretHandler, []string{"DELETE"}))

	return http.ListenAndServe(listenAddress, nil)
}
