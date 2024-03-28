package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/oliveagle/jsonpath"
	"github.com/patrickmn/go-cache"
	"sync"
	"time"
)

type TokenType string

var (
	OAUTH2 TokenType = "OAuth2"
	SIGN   TokenType = "Signature"
)

// Token 信息
type Token struct {
	// Type Token类型
	Type TokenType `json:"type" binding:"required"`
	// Token值
	Value string `json:"value" binding:"required"`
	// 租户id
	Tid int64 `json:"tid" binding:"tid"`
	// 用户id
	Uid int64 `json:"uid" binding:"required"`
	// 用户名称
	Uname string `json:"uname" binding:"uname"`
	// 扩展参数
	Params map[string]interface{} `json:"params" binding:"required"`
}

// XyzClaims 自定义JWT claims
type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

// KeyInf JWT解析key
type KeyInf struct {
	Id  string `json:"id" binding:"required"`
	Key string `json:"key" binding:"required"`
	Alg string `json:"alg" binding:"required"`
}

// EncryptionInf AES加密配置信息
type EncryptionInf struct {
	// APP id
	AppId string `json:"appId" binding:"required"`
	// APP Secret
	AppSecret string `json:"appSecret" binding:"required"`
	// 获取Token key时，AES加密key
	AESKey string `json:"aesKey" binding:"required"`
	// 获取Token key时，AES加密iv
	AESIv string `json:"aesIv" binding:"required"`
	// 租户id
	TenantId int32 `json:"tenantId" binding:"required"`
	// 用户名称
	Username string `json:"username" binding:"required"`
	// 用户id
	UserId int64 `json:"userId" binding:"required"`
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

		oauth2TokenKeyUrl := env.GetString("OAUTH2_TOKEN_KEY_ENDPOINT", "https://127.0.0.1:6666/oauth2/token-key")
		appId := env.GetString("OAUTH2_APP_ID", "")
		appSecret := env.GetString("OAUTH2_APP_SECRET", "")
		var timestamp, sgn string
		if appId != "" && appSecret != "" {
			timestamp, sgn = sign.SignWithTimestamp(appSecret, "")
		}
		var respBytes []byte
		respBytes, err = utils.Get(oauth2TokenKeyUrl, sgn, appId, timestamp)
		if err != nil {
			return
		}

		var resp = map[string]interface{}{}
		err = json.Unmarshal(respBytes, &resp)
		if err != nil {
			return
		}
		keyJsonPath := env.GetString("OAUTH2_TOKEN_KEY_JP", "$.data.key")
		var key interface{}
		key, err = jsonpath.JsonPathLookup(resp, keyJsonPath)
		if err != nil {
			return
		}
		base64TokenKey := key.(string)
		aesKey := env.GetString("OAUTH2_TOKEN_KEY_AES_KEY", "")
		aesIv := env.GetString("OAUTH2_TOKEN_KEY_AES_IV", "")
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
