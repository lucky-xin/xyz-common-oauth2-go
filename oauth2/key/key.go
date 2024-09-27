package key

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf/rest"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"github.com/oliveagle/jsonpath"
	"github.com/patrickmn/go-cache"
	"github.com/tjfoc/gmsm/sm2"
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

		oauth2TokenKeyUrl := env.GetString("OAUTH2_ISSUER_ENDPOINT", "https://127.0.0.1:6666") + "/oauth2/token-key"
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
		hexTokenKey := key.(string)
		privateKeyHex := env.GetString("OAUTH2_TOKEN_KEY_SM2_PRIVATE_KEY", "")
		publicKeyHex := env.GetString("OAUTH2_TOKEN_KEY_SM2_PUBLIC_KEY", "")
		encrypt, err := encryption.NewSM2Encryption(publicKeyHex, privateKeyHex)
		if err != nil {
			return nil, err
		}
		tk, err = encrypt.Decrypt(hexTokenKey, sm2.C1C3C2)
		if err != nil {
			return nil, err
		}
		byts = []byte(tk)
		c.Set(cacheKey, byts, rest.expiresMs)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}

func Create(svc conf.EncryptInfSvc, expiresMs time.Duration) *RestTokenKey {
	return &RestTokenKey{svc, expiresMs}
}

func CreateWithEnv() *RestTokenKey {
	return &RestTokenKey{
		rest.CreateWithEnv(),
		time.Duration(env.GetInt64("OAUTH2_TOKEN_KEY_CACHE_EXPIRES_MS", 6*time.Hour.Milliseconds())) * time.Millisecond,
	}
}
