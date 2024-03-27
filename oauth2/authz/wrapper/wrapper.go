package wrapper

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	xjwt "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/jwt"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/signature"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/patrickmn/go-cache"
	"net/http"
	"sync"
	"time"
)

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

		var keyInf = &r.Resp[oauth2.KeyInf]{}
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

type Checker struct {
	resolver resolver.TokenResolver
	tokenKey authz.TokenKey
	checkers map[oauth2.TokenType]authz.Checker
}

func CreateWithEnv() authz.Checker {
	return &Checker{
		resolver: resolver.CreateWithEnv(),
		tokenKey: RestTokenKey,
		checkers: map[oauth2.TokenType]authz.Checker{
			oauth2.OAUTH2: xjwt.CreateWithEnv(),
			oauth2.SIGN:   signature.CreateWithEnv(),
		},
	}
}

func Create(r resolver.TokenResolver, tk authz.TokenKey, cs map[oauth2.TokenType]authz.Checker) (c *Checker, err error) {
	return &Checker{
		resolver: r, tokenKey: tk, checkers: cs,
	}, nil
}

func (checker *Checker) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		byts, err := RestTokenKey()
		if err != nil {
			c.JSON(http.StatusUnauthorized, r.Failed(err.Error()))
			c.Abort()
			return
		}
		verify, err := checker.CheckWithContext(byts, c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, r.Failed(err.Error()))
			c.Abort()
			return
		}
		c.Set("uid", verify.UserId)
		c.Set("uname", verify.Username)
		c.Set("tid", verify.TenantId)
		c.Next()
	}
}

func (checker *Checker) TokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (u *oauth2.XyzClaims, err error) {
	delegate := checker.checkers[token.Type]
	if delegate == nil {
		err = errors.New(string("unsupported token type:" + token.Type))
		return
	}
	return delegate.Check(key, token)
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}
