package oauth2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/patrickmn/go-cache"
	"sort"
	"strings"
	"sync"
	"time"
)

type RestEncryptionInfSvc struct {
	EncryptionConfUrl string
	c                 *cache.Cache
	// 当前应用appId
	appId string
	// 当前应用appSecret
	appSecret string

	mua sync.RWMutex
}

func NewRestConfigSignatureWithEnv() Signature {
	return NewRestConfigSignature(
		env.GetString("OAUTH2_ENCRYPTION_CONF_URL", "http://127.0.0.1:4000/encryption-conf/app-id"),
	)
}

func NewRestEncryptionInfSvc(encryptionConfUrl string) EncryptionInfSvc {
	return &RestEncryptionInfSvc{
		EncryptionConfUrl: encryptionConfUrl,
		c:                 cache.New(12*time.Hour, 6*time.Hour),
	}
}

func NewRestConfigSignature(encryptionConfUrl string) Signature {
	return &ConfigSignature{ConfSvc: NewRestEncryptionInfSvc(encryptionConfUrl)}
}

func NewSignature(confSvc EncryptionInfSvc) Signature {
	return &ConfigSignature{ConfSvc: confSvc}
}

func (restSign *ConfigSignature) EncryptionInfSvc() (EncryptionInfSvc, error) {
	return restSign.ConfSvc, nil
}

func (restSign *ConfigSignature) CreateSign(params map[string]interface{}, appSecret, timestamp string) (string, error) {
	return CreateSign(params, appSecret, timestamp)
}

func CreateSign(params map[string]interface{}, appSecret, timestamp string) (string, error) {
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

func (restSign *ConfigSignature) Check(token *Token) (*XyzClaims, error) {
	reqAppId := token.Params["App-Id"].(string)
	reqTimestamp := token.Params["Timestamp"].(string)
	if conf, err := restSign.ConfSvc.GetEncryptionInf(reqAppId); err != nil {
		appSecret := conf.AppSecret
		username := conf.Username
		userId := conf.UserId
		if sgn, err := restSign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			return &XyzClaims{
				Username: username,
				UserId:   userId,
				TenantId: conf.TenantId,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Subject:   username,
				},
			}, nil
		}
	}
	return nil, nil
}

func (svc *RestEncryptionInfSvc) GetEncryptionInf(appId string) (*EncryptionInf, error) {
	key := "app_id:" + appId
	if val, b := svc.c.Get(key); b {
		s := val.(EncryptionInf)
		return &s, nil
	}

	svc.mua.Lock()
	defer svc.mua.Unlock()
	if val, b := svc.c.Get(key); b {
		s := val.(EncryptionInf)
		return &s, nil
	}
	var url string
	if svc.EncryptionConfUrl[len(svc.EncryptionConfUrl)-1] == '/' {
		url = svc.EncryptionConfUrl + appId
	} else {
		url = svc.EncryptionConfUrl + "/" + appId
	}

	timestamp, sgn := sign.SignWithTimestamp(svc.appSecret, "")
	if respBytes, err := Get(url, sgn, appId, timestamp); err != nil {
		return nil, err
	} else {
		var resp = &r.Resp[EncryptionInf]{}
		err = json.Unmarshal(respBytes, resp)
		data := resp.BizData
		svc.c.Set(key, data, 24*time.Hour)
		return &data, err
	}
}
