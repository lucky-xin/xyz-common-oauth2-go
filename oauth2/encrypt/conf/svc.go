package conf

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
	"sync"
	"time"
)

type Svc struct {
	EncryptionConfUrl string
	c                 *cache.Cache
	// 当前应用appId
	appId string
	// 当前应用appSecret
	appSecret string

	mua     sync.RWMutex
	encrypt *encryption.SM2
}

func Create(encryptionConfUrl string, sm2 *encryption.SM2, expireMs, cleanupMs time.Duration) *Svc {
	return &Svc{
		encrypt:           sm2,
		EncryptionConfUrl: encryptionConfUrl,
		c:                 cache.New(expireMs, cleanupMs),
		appId:             env.GetString("OAUTH2_APP_ID", ""),
		appSecret:         env.GetString("OAUTH2_APP_SECRET", ""),
	}
}

func CreateWithEnv() *Svc {
	expireMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_EXPIRE_MS", 6*time.Hour.Milliseconds())
	cleanupMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CLEANUP_MS", 6*time.Hour.Milliseconds())
	privateKeyHex := env.GetString("OAUTH2_SM2_PRIVATE_KEY", "")
	publicKeyHex := env.GetString("OAUTH2_SM2_PUBLIC_KEY", "")
	encrypt, err := encryption.NewSM2(publicKeyHex, privateKeyHex)
	if err != nil {
		panic(err)
	}
	return Create(
		env.GetString("OAUTH2_ISSUER_ENDPOINT", "https://127.0.0.1:6666")+"/oauth2/encryption/config",
		encrypt,
		time.Duration(expireMs)*time.Millisecond,
		time.Duration(cleanupMs)*time.Millisecond,
	)
}

func (svc *Svc) GetEncryptInf(appId string) (*oauth2.EncryptionInf, error) {
	key := "app_id:" + appId
	if val, b := svc.c.Get(key); b {
		s := val.(*oauth2.EncryptionInf)
		return s, nil
	}

	svc.mua.Lock()
	defer svc.mua.Unlock()
	if val, b := svc.c.Get(key); b {
		s := val.(*oauth2.EncryptionInf)
		return s, nil
	}
	var url string
	queryString := "app_id=" + appId
	url = svc.EncryptionConfUrl + "?" + queryString
	timestamp, sgn := sign.SignWithTimestamp(svc.appSecret, queryString)
	if respBytes, err := utils.Get(url, sgn, appId, timestamp); err != nil {
		return nil, err
	} else {
		var resp2 = &r.Resp[string]{}
		err = json.Unmarshal(respBytes, resp2)
		if err != nil {
			return nil, err
		}
		var conf = &oauth2.EncryptionInf{}
		err = svc.encrypt.DecryptObject(resp2.BizData, sm2.C1C3C2, conf)
		if err != nil {
			return nil, err
		}
		svc.c.Set(key, conf, 24*time.Hour)
		return conf, nil
	}
}
