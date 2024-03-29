package rest

import (
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/patrickmn/go-cache"
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

	mua sync.RWMutex
}

func Create(encryptionConfUrl string, expireMs, cleanupMs time.Duration) *Svc {
	return &Svc{
		EncryptionConfUrl: encryptionConfUrl,
		c:                 cache.New(expireMs, cleanupMs),
		appId:             env.GetString("OAUTH2_APP_ID", ""),
		appSecret:         env.GetString("OAUTH2_APP_SECRET", ""),
	}
}

func CreateWithEnv() *Svc {
	expireMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CACHE_EXPIRE_MS", 6*time.Hour.Milliseconds())
	cleanupMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CACHE_CLEANUP_MS", 6*time.Hour.Milliseconds())
	return Create(
		env.GetString("OAUTH2_ENCRYPTION_CONF_ENDPOINT", "http://127.0.0.1:4000/encryption-conf"),
		time.Duration(expireMs)*time.Millisecond,
		time.Duration(cleanupMs)*time.Millisecond,
	)
}

func (svc *Svc) GetEncryptInf(appId string) (*oauth2.EncryptionInf, error) {
	key := "app_id:" + appId
	if val, b := svc.c.Get(key); b {
		s := val.(oauth2.EncryptionInf)
		return &s, nil
	}

	svc.mua.Lock()
	defer svc.mua.Unlock()
	if val, b := svc.c.Get(key); b {
		s := val.(oauth2.EncryptionInf)
		return &s, nil
	}
	var url string
	if svc.EncryptionConfUrl[len(svc.EncryptionConfUrl)-1] == '/' {
		url = svc.EncryptionConfUrl + appId
	} else {
		url = svc.EncryptionConfUrl + "/" + appId
	}

	timestamp, sgn := sign.SignWithTimestamp(svc.appSecret, "")
	if respBytes, err := utils.Get(url, sgn, appId, timestamp); err != nil {
		return nil, err
	} else {
		var resp = &r.Resp[oauth2.EncryptionInf]{}
		err = json.Unmarshal(respBytes, resp)
		data := resp.BizData
		svc.c.Set(key, data, 24*time.Hour)
		return &data, nil
	}
}
