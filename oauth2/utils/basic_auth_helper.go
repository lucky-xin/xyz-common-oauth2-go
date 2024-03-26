package utils

import (
	"encoding/base64"
)

func ToBasicAuth(cliId, cliSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cliId+":"+cliSecret))
}
