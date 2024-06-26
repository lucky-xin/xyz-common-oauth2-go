package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf/rest"
	"sort"
	"strings"
	"time"
)

type Signature struct {
	ConfSvc conf.EncryptInfSvc
}

func CreateWithRest(encryptionConfUrl string, expireMs, cleanupMs time.Duration) *Signature {
	return &Signature{ConfSvc: rest.Create(encryptionConfUrl, expireMs, cleanupMs)}
}
func CreateWithEnv() *Signature {
	return Create(rest.CreateWithEnv())
}

func Create(confSvc conf.EncryptInfSvc) *Signature {
	return &Signature{ConfSvc: confSvc}
}

func (restSign *Signature) GetEncryptionInfSvc() (conf.EncryptInfSvc, error) {
	return restSign.ConfSvc, nil
}

func (restSign *Signature) CreateSign(params map[string]string, appSecret, timestamp string) (string, error) {
	return CreateSign(params, appSecret, timestamp)
}

func (restSign *Signature) Check(token *oauth2.Token) (*oauth2.XyzClaims, error) {
	reqAppId := token.Params[oauth2.AppFieldName]
	reqTimestamp := token.Params[oauth2.TimestampFieldName]
	if inf, err := restSign.ConfSvc.GetEncryptInf(reqAppId); err != nil {
		appSecret := inf.AppSecret
		username := inf.Username
		userId := inf.UserId
		if sgn, err := restSign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			return &oauth2.XyzClaims{
				Username: username,
				UserId:   userId,
				TenantId: inf.TenantId,
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

func CreateSign(params map[string]string, appSecret, timestamp string) (string, error) {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	length := len(keys)
	for idx := range keys {
		key := keys[idx]
		if oauth2.AppFieldName == key || oauth2.TimestampFieldName == key {
			continue
		}
		buffer.WriteString(fmt.Sprintf("%v", params[key]))
		if idx != length-1 {
			buffer.WriteString("&")
		}
	}
	stringToSign := []byte(timestamp + "\n" + appSecret + "\n" + buffer.String())
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write(stringToSign) // nolint: errcheck
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
