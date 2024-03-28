package key

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/oliveagle/jsonpath"
	"github.com/patrickmn/go-cache"
	"log"
	"sync"
	"time"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type RestTokenKey struct {
	encryptSvc conf.EncryptInfSvc
	expiresMs  time.Duration
}

func (rest *RestTokenKey) Get() (byts []byte, err error) {
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
		var rbyts []byte
		rbyts, err = utils.Get(oauth2TokenKeyUrl, sgn, appId, timestamp)
		if err != nil {
			return
		}
		log.Println("get token key resp:", string(rbyts))
		var resp = map[string]interface{}{}
		err = json.Unmarshal(rbyts, &resp)
		if err != nil {
			return
		}
		keyJsonPath := env.GetString("OAUTH2_TOKEN_KEY_JP", "$.data.key")
		var key interface{}
		key, err = jsonpath.JsonPathLookup(resp, keyJsonPath)
		if err != nil {
			log.Println("json path lookup failed,", err.Error())
			return
		}
		base64TokenKey := key.(string)
		aesKey := env.GetString("OAUTH2_TOKEN_KEY_AES_KEY", "")
		aesIv := env.GetString("OAUTH2_TOKEN_KEY_AES_IV", "")
		if (aesKey == "" || aesIv == "") && rest.encryptSvc != nil {
			inf, err := rest.encryptSvc.GetEncryptInf(appId)
			if err != nil {
				return nil, err
			}
			aesKey = inf.AESKey
			aesIv = inf.AESIv
		}
		encryptor := aescbc.Encryptor{Key: aesKey, Iv: aesIv}
		byts, err = encryptor.Decrypt(base64TokenKey)
		if err != nil {
			return
		}
		c.Set(cacheKey, byts, rest.expiresMs)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}

func Create(svc conf.EncryptInfSvc, expiresMs time.Duration) *RestTokenKey {
	return &RestTokenKey{svc, expiresMs}
}
