package key

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"github.com/patrickmn/go-cache"
	"github.com/tjfoc/gmsm/sm2"
	"sync"
	"time"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type TokenKey struct {
	Id  string `json:"id"`
	Key string `json:"key"`
	Alg string `json:"alg"`
}

type RestTokenKeySvc struct {
	encryptSvc conf.EncryptInfSvc
	expiresMs  time.Duration
	sm2        *encryption.SM2
	signature  *sign.Signature
}

func (rest *RestTokenKeySvc) GetTokenKey() (byts []byte, err error) {
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
		rbyts, err := rest.signature.SignGet(oauth2TokenKeyUrl, map[string]string{})
		if err != nil {
			return nil, err
		}
		var resp = r.Resp[string]{}
		err = json.Unmarshal(rbyts, &resp)
		if err != nil {
			return nil, err
		}
		var tokenKeyText []byte
		tokenKeyText, err = rest.sm2.DecryptHex(resp.Data(), sm2.C1C3C2)
		if err != nil {
			return nil, err
		}
		var t = TokenKey{}
		err = json.Unmarshal(tokenKeyText, &t)
		if err != nil {
			return nil, err
		}
		byts = []byte(t.Key)
		c.Set(cacheKey, byts, rest.expiresMs)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}

func Create(svc conf.EncryptInfSvc, expiresMs time.Duration) *RestTokenKeySvc {
	privateKeyHex := env.GetString("OAUTH2_SM2_PRIVATE_KEY", "")
	publicKeyHex := env.GetString("OAUTH2_SM2_PUBLIC_KEY", "")
	encrypt, err := encryption.NewSM2(publicKeyHex, privateKeyHex)
	if err != nil {
		println(err)
	}
	return &RestTokenKeySvc{encryptSvc: svc,
		expiresMs: expiresMs,
		sm2:       encrypt,
		signature: sign.CreateWithEnv(),
	}
}

func CreateWithEnv() *RestTokenKeySvc {
	return Create(
		conf.CreateWithEnv(),
		time.Duration(env.GetInt64("OAUTH2_TOKEN_KEY_EXPIRES_MS", 6*time.Hour.Milliseconds()))*time.Millisecond,
	)
}
