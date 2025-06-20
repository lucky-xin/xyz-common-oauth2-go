package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"io"
	"net/http"
)

var (
	HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

func Get(url, sgn, appId, timestamp string) ([]byte, error) {
	if req, err := http.NewRequest(http.MethodGet, url, nil); err != nil {
		return nil, err
	} else {
		if sgn != "" {
			req.Header.Set("Authorization", "Signature "+sgn)
			req.Header.Set(oauth2.APP_ID_HEADER_NAME, appId)
			req.Header.Set(oauth2.TIMESTAMP_HEADER_NAME, timestamp)
		}
		if resp, err := HttpClient.Do(req); err == nil {
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

func ReqParams(c *gin.Context) (map[string]interface{}, error) {
	contentType := c.ContentType()
	method := c.Request.Method
	if "application/json" == contentType && (method == http.MethodPut || method == http.MethodPost) {
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
