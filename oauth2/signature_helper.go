package oauth2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/patrickmn/go-cache"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

var (
	cli = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	c = cache.New(24*time.Hour, 24*time.Hour)
)

func GenSign(params map[string]interface{}, appSecret, timestamp string) (string, error) {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	length := len(keys)
	for idx := range keys {
		buffer.WriteString(fmt.Sprintf("%v", params[keys[idx]]))
		if idx != length-1 {
			buffer.WriteString("&")
		}
	}
	stringToSign := []byte(timestamp + "\n" + appSecret + "\n" + buffer.String())
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write(stringToSign) // nolint: errcheck
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func Get(url, sgn, appId, timestamp string) ([]byte, error) {
	if req, err := http.NewRequest("GET", url, nil); err != nil {
		return nil, err
	} else {
		if sgn != "" {
			req.Header.Set("Authorization", "Signature "+sgn)
			req.Header.Set("App-Id", appId)
			req.Header.Set("Timestamp", timestamp)
		}
		if resp, err := cli.Do(req); err == nil {
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					panic(err)
				}
			}(resp.Body)
			return io.ReadAll(resp.Body)
		} else {
			return nil, err
		}
	}
}

var mua sync.RWMutex

func GetEncryptionInf(id string) (*EncryptionInf, error) {
	key := "app_id:" + id
	if val, b := c.Get(key); b {
		s := val.(EncryptionInf)
		return &s, nil
	}

	mua.Lock()
	defer mua.Unlock()
	appId := env.GetString("APP_ID", "")
	appSecret := env.GetString("APP_SECRET", "")
	queryAppIdUrl := env.GetString("UPMS_ENDPOINT", "http://127.0.0.1:4000") + "/encryption-conf/app-id/" + id
	timestamp, sgn := sign.SignWithTimestamp(appSecret, "")
	if respBytes, err := Get(queryAppIdUrl, sgn, appId, timestamp); err != nil {
		return nil, err
	} else {
		var resp = &r.Resp[EncryptionInf]{}
		err = json.Unmarshal(respBytes, resp)
		data := resp.BizData
		c.Set(key, data, 24*time.Hour)
		return &data, err
	}
}

func ReqParams(c *gin.Context) (map[string]interface{}, error) {
	contentType := c.ContentType()
	method := c.Request.Method
	if "application/json" == contentType && (method == "POST" || method == "PUT") {
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		var temp = make(map[string]interface{})
		err := json.Unmarshal(bodyBytes, &temp)
		if err != nil {
			return nil, err
		}
		var postMap = make(map[string]interface{})
		for k, _ := range postMap {
			postMap[k] = 1
		}
		return postMap, nil
	}

	var dataMap = make(map[string]interface{})
	for k := range c.Request.URL.Query() {
		dataMap[k] = c.Query(k)
	}
	return dataMap, nil

}
