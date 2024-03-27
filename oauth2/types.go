package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/patrickmn/go-cache"
	"sync"
	"time"
)

type TokenType string

var (
	OAUTH2 TokenType = "OAuth2"
	SIGN   TokenType = "Signature"
)

type Token struct {
	Type   TokenType              `json:"type" binding:"required"`
	Value  string                 `json:"value" binding:"required"`
	Params map[string]interface{} `json:"params" binding:"required"`
}
type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

type KeyInf struct {
	Id  string `json:"id" binding:"required"`
	Key string `json:"key" binding:"required"`
	Alg string `json:"alg" binding:"required"`
}

type EncryptionInf struct {
	AppId     string `json:"appId" binding:"required"`
	AppSecret string `json:"appSecret" binding:"required"`
	AESKey    string `json:"aesKey" binding:"required"`
	AESIv     string `json:"aesIv" binding:"required"`
	TenantId  int32  `json:"tenantId" binding:"required"`
	Username  string `json:"username" binding:"required"`
	UserId    int64  `json:"userId" binding:"required"`
}

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

func RestTokenKey() (byts []byte, err error) {
	tk := env.GetString("OAUTH2_TOKEN_KEY", "")
	if tk != "" {
		byts = []byte(tk)
		return
	}

	cacheKey := "token_key"
	if tokenKey, exist := c.Get(cacheKey); !exist {
		mu.Lock()
		defer mu.Unlock()
		if tokenKey, exist = c.Get(cacheKey); exist {
			byts = tokenKey.([]byte)
			return
		}

		oauth2TokenKeyUrl := env.GetString("OAUTH2_TOKEN_KEY_URL", "https://127.0.0.1:6666/oauth2/token-key")
		appId := env.GetString("APP_ID", "")
		appSecret := env.GetString("APP_SECRET", "")
		var timestamp, sgn string
		if appId != "" && appSecret != "" {
			timestamp, sgn = sign.SignWithTimestamp(appSecret, "")
		}
		var respBytes []byte
		respBytes, err = utils.Get(oauth2TokenKeyUrl, sgn, appId, timestamp)
		if err != nil {
			return
		}

		var keyInf = &r.Resp[KeyInf]{}
		err = json.Unmarshal(respBytes, keyInf)
		if err != nil {
			return
		}
		base64TokenKey := keyInf.BizData.Key
		aesKey := env.GetString("AES_KEY", "")
		aesIv := env.GetString("AES_IV", "")
		if aesKey != "" && aesIv != "" {
			encryptor := aescbc.Encryptor{Key: aesKey, Iv: aesIv}
			byts, err = encryptor.Decrypt(base64TokenKey)
			if err != nil {
				return
			}
		} else {
			byts, err = base64.StdEncoding.DecodeString(base64TokenKey)
			if err != nil {
				return
			}
		}
		c.Set(cacheKey, byts, 24*time.Hour)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}
