package oauth2

import (
	"encoding/base64"
)

func CreateBasicAuth(cliId, cliSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cliId+":"+cliSecret))
}
