package unus

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"code.leif.uk/lwg/unus/internal/whereami"
)

// default route handler
func frontPageHandler(w http.ResponseWriter, r *http.Request) {
	file, err := os.ReadFile(fmt.Sprintf("%s%s", whereami.Root, "/web/index.html"))
	if err != nil {
		fmt.Fprintln(w, "something went wrong")
		log.Println(err)
		return
	}

	writeResponseBytes(w, "text/html", file)
}
