package details

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
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

type RestUserDetailsSvc struct {
	expiresMs time.Duration
	sm2       *encryption.SM2
	signature *sign.Signature
}

func Create(expiresMs time.Duration, sm2 *encryption.SM2, signature *sign.Signature) *RestUserDetailsSvc {
	return &RestUserDetailsSvc{expiresMs: expiresMs, sm2: sm2, signature: signature}
}

func CreateWithEnv() *RestUserDetailsSvc {
	expireMs := env.GetInt64("OAUTH2_USER_DETAILS_EXPIRE_MS", 12*time.Hour.Milliseconds())
	privateKeyHex := env.GetString("OAUTH2_SM2_PRIVATE_KEY", "")
	publicKeyHex := env.GetString("OAUTH2_SM2_PUBLIC_KEY", "")
	encrypt, err := encryption.NewSM2(publicKeyHex, privateKeyHex)
	if err != nil {
		println(err)
	}
	return Create(
		time.Duration(expireMs)*time.Millisecond,
		encrypt,
		sign.CreateWithEnv(),
	)
}

func (rest *RestUserDetailsSvc) Get(username string) (details *oauth2.UserDetails, err error) {
	cacheKey := "user:" + username
	if cached, exist := c.Get(cacheKey); !exist {
		mu.Lock()
		defer mu.Unlock()
		if cached, exist = c.Get(cacheKey); exist {
			details = cached.(*oauth2.UserDetails)
			return
		}

		userDetailsUrl := env.GetString("OAUTH2_ISSUER_ENDPOINT", "https://127.0.0.1:6666") + "/oauth2/user/details"
		byts, err := rest.signature.SignGet(userDetailsUrl, map[string]string{"username": username})
		if err != nil {
			return nil, err
		}
		var res = r.Resp[string]{}
		err = json.Unmarshal(byts, &res)
		if err != nil {
			return
		}
		hexString := res.Data()
		log.Println("hexString:", hexString)
		details = &oauth2.UserDetails{}
		log.Println("DecryptObject...")
		err = rest.sm2.DecryptObject(hexString, sm2.C1C3C2, details)
		if err != nil {
			return nil, err
		}
		c.Set(cacheKey, details, rest.expiresMs)
	} else {
		details = cached.(*oauth2.UserDetails)
	}
	return
}
