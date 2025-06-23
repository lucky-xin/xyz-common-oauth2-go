package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type Signature struct {
	appId     string
	appSecret string
}

func CreateWithEnv() *Signature {
	return Create(
		env.GetString("OAUTH2_APP_ID", ""),
		env.GetString("OAUTH2_APP_SECRET", ""),
	)
}

func Create(appId string, appSecret string) *Signature {
	return &Signature{appId: appId, appSecret: appSecret}
}

func (restSign *Signature) SignGet(baseUrl string, params map[string]string) (byts []byte, err error) {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	suffix, sgn, err := restSign.CreateSign(params, restSign.appSecret, timestamp)
	if err != nil {
		return nil, err
	}
	return utils.Get(baseUrl+"?"+suffix, sgn, restSign.appId, timestamp)
}

func (restSign *Signature) CreateSign(params map[string]string, appSecret, timestamp string) (string, string, error) {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	vals := url.Values{}

	length := len(keys)
	for idx := range keys {
		key := keys[idx]
		if oauth2.APP_ID_HEADER_NAME == key || oauth2.TIMESTAMP_HEADER_NAME == key {
			continue
		}
		vals.Add(key, params[key])
		buffer.WriteString(fmt.Sprintf("%s=%v", key, params[key]))
		if idx != length-1 {
			buffer.WriteString("&")
		}
	}
	stringToSign := []byte(timestamp + "\n" + appSecret + "\n" + buffer.String())
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write(stringToSign) // nolint: errcheck
	return vals.Encode(), base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
