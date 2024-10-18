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
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"sort"
	"strings"
	"time"
)

type Signature struct {
	DetailsSvc authz.UserDetailsSvc
	EncryptSvc conf.EncryptInfSvc
}

func CreateWithRest(expireMs time.Duration) *Signature {
	return &Signature{DetailsSvc: details.Create(expireMs)}
}
func CreateWithEnv() *Signature {
	return Create(
		details.CreateWithEnv(),
		conf.CreateWithEnv(),
	)
}

func Create(detailsSvc authz.UserDetailsSvc, encryptSvc conf.EncryptInfSvc) *Signature {
	return &Signature{DetailsSvc: detailsSvc, EncryptSvc: encryptSvc}
}

func (restSign *Signature) CreateSign(params map[string]string, appSecret, timestamp string) (string, error) {
	return CreateSign(params, appSecret, timestamp)
}

func (restSign *Signature) Check(token *oauth2.Token) (details *oauth2.UserDetails, err error) {
	reqAppId := token.Params[oauth2.APP_ID_HEADER_NAME]
	reqTimestamp := token.Params[oauth2.TIMESTAMP_HEADER_NAME]
	if inf, err := restSign.EncryptSvc.GetEncryptInf(reqAppId); err == nil {
		appSecret := inf.AppSecret
		if sgn, err := restSign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			details, err = restSign.DetailsSvc.Get(inf.Username)
			if err != nil {
				return nil, err
			}
			details.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * 10))
			details.NotBefore = jwt.NewNumericDate(time.Now())
			details.IssuedAt = jwt.NewNumericDate(time.Now())
			return details, nil
		}
	} else {
		return nil, err
	}
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
		if oauth2.APP_ID_HEADER_NAME == key || oauth2.TIMESTAMP_HEADER_NAME == key {
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
