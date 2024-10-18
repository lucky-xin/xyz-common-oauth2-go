package details

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"github.com/patrickmn/go-cache"
	"github.com/tjfoc/gmsm/sm2"
	"net/url"
	"sync"
	"time"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type RestUserDetailsSvc struct {
	expiresMs time.Duration
}

func Create(expiresMs time.Duration) *RestUserDetailsSvc {
	return &RestUserDetailsSvc{expiresMs}
}

func CreateWithEnv() *RestUserDetailsSvc {
	expireMs := env.GetInt64("OAUTH2_USER_DETAILS_EXPIRE_MS", 30*time.Second.Milliseconds())
	return Create(
		time.Duration(expireMs) * time.Millisecond,
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
		appId := env.GetString("OAUTH2_APP_ID", "")
		appSecret := env.GetString("OAUTH2_APP_SECRET", "")
		var timestamp, sgn string
		queryString := "username=" + username
		timestamp, sgn = sign.SignWithTimestamp(appSecret, queryString)
		var rbyts []byte
		uri := userDetailsUrl + "?username=" + url.QueryEscape(username)
		rbyts, err = utils.Get(uri, sgn, appId, timestamp)
		if err != nil {
			return
		}
		var res = r.Resp[string]{}
		err = json.Unmarshal(rbyts, &res)
		if err != nil {
			return
		}
		hexString := res.Data()
		privateKeyHex := env.GetString("OAUTH2_SM2_PRIVATE_KEY", "")
		publicKeyHex := env.GetString("OAUTH2_SM2_PUBLIC_KEY", "")
		encrypt, err := encryption.NewSM2(publicKeyHex, privateKeyHex)
		if err != nil {
			return nil, err
		}
		details = &oauth2.UserDetails{}
		err = encrypt.DecryptObject(hexString, sm2.C1C3C2, details)
		if err != nil {
			return nil, err
		}
		c.Set(cacheKey, details, rest.expiresMs)
	} else {
		details = cached.(*oauth2.UserDetails)
	}
	return
}
