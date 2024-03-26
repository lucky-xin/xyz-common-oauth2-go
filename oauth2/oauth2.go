package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/patrickmn/go-cache"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Checker struct {
	mu            sync.RWMutex
	cache         *cache.Cache
	tokenResolver TokenResolver
}

func NewChecker() (*Checker, error) {
	return &Checker{
		cache:         cache.New(24*time.Hour, 24*time.Hour),
		tokenResolver: NewDefaultTokenResolver(),
	}, nil
}

func NewWithTokenResolver(tokenResolver TokenResolver) *Checker {
	return &Checker{
		cache:         cache.New(24*time.Hour, 24*time.Hour),
		tokenResolver: tokenResolver,
	}
}

func (check *Checker) GetTokenKey() (byts []byte, err error) {
	tk := env.GetString("OAUTH2_TOKEN_KEY", "")
	if tk != "" {
		byts = []byte(tk)
		return
	}

	cacheKey := "token_key"
	if tokenKey, exist := check.cache.Get(cacheKey); !exist {
		check.mu.Lock()
		defer check.mu.Unlock()
		if tokenKey, exist = check.cache.Get(cacheKey); exist {
			byts = tokenKey.([]byte)
			return
		}

		oauth2TokenKeyUrl := env.GetString("OAUTH2_ENDPOINT", "") + "/oauth2/octet-key"
		appId := env.GetString("APP_ID", "")
		appSecret := env.GetString("APP_SECRET", "")
		var timestamp, sgn string
		if appId != "" && appSecret != "" {
			timestamp, sgn = sign.SignWithTimestamp(appSecret, "")
		}
		var respBytes []byte
		respBytes, err = Get(oauth2TokenKeyUrl, sgn, appId, timestamp)
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
		check.cache.Set(cacheKey, byts, 24*time.Hour)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}

func (check *Checker) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		verify, err := check.Check(c)
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

func (check *Checker) Check(c *gin.Context) (*PistonClaims, error) {
	token := check.tokenResolver.Resolve(c)
	if token == nil {
		return nil, errors.New("unauthorized")
	}
	return check.DecodeToken(token)
}

func (check *Checker) DecodeToken(token *Token) (*PistonClaims, error) {
	if token == nil {
		return nil, errors.New("unauthorized")
	}
	switch token.Type {
	case OAUTH2:
		return check.checkOAuth2(token)
	case SIGN:
		return check.checkSign(token)
	}

	return nil, errors.New("unauthorized")
}

func (check *Checker) checkSign(token *Token) (*PistonClaims, error) {
	reqAppId := token.Params["App-Id"].(string)
	reqTimestamp := token.Params["Timestamp"].(string)
	if encryptionInf, err := GetEncryptionInf(reqAppId); err != nil {
		appSecret := encryptionInf.AppSecret
		username := encryptionInf.Username
		userId := encryptionInf.UserId
		if sgn, err := GenSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			now := jwt.TimeFunc().Unix()
			return &PistonClaims{
				Username: username,
				UserId:   userId,
				TenantId: encryptionInf.TenantId,
				StandardClaims: jwt.StandardClaims{
					IssuedAt:  now,
					ExpiresAt: now + 30,
					Subject:   username,
				},
			}, nil
		}
	}
	return nil, nil
}

func (check *Checker) checkOAuth2(token *Token) (u *PistonClaims, err error) {
	key, err := check.GetTokenKey()
	if err != nil {
		return
	}
	claims := &PistonClaims{}
	parser := jwt.Parser{ValidMethods: []string{"HS512"}, UseJSONNumber: false, SkipClaimsValidation: false}
	if _, err := parser.ParseWithClaims(token.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}); err == nil {
		return claims, nil
	} else {
		return nil, err
	}
}
