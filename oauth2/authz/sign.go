package authz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	osign "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/patrickmn/go-cache"
	"strings"
	"sync"
	"time"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type SignChecker struct {
	sign     types.Signature
	resolver types.TokenResolver
}

func NewSignCheckerWithEnv() *SignChecker {
	return &SignChecker{
		sign:     osign.NewRestConfigSignatureWithEnv(),
		resolver: resolver.NewDefaultTokenResolverWithEnv(),
	}
}

func NewRestSignChecker(encryptionConfUrl string, resolver types.TokenResolver) *SignChecker {
	signature := osign.NewRestConfigSignature(encryptionConfUrl)
	return &SignChecker{
		sign:     signature,
		resolver: resolver,
	}
}

func NewSignChecker(confSvc types.EncryptionInfSvc, resolver types.TokenResolver) *SignChecker {
	signature := osign.NewSignature(confSvc)
	return &SignChecker{
		sign:     signature,
		resolver: resolver,
	}
}

func (checker *SignChecker) TokenResolver() types.TokenResolver {
	return checker.resolver
}

func (checker *SignChecker) Check(key []byte, token *types.Token) (*types.XyzClaims, error) {
	reqAppId := token.Params["App-Id"].(string)
	reqTimestamp := token.Params["Timestamp"].(string)
	confSvc, err := checker.sign.EncryptionInfSvc()
	if err != nil {
		return nil, err
	}
	if conf, err := confSvc.GetEncryptionInf(reqAppId); err != nil {
		appSecret := conf.AppSecret
		username := conf.Username
		userId := conf.UserId
		if sgn, err := checker.sign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			return &types.XyzClaims{
				Username: username,
				UserId:   userId,
				TenantId: conf.TenantId,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Subject:   username,
				},
			}, nil
		}
	}
	return nil, nil
}

func (checker *SignChecker) CheckWithContext(key []byte, c *gin.Context) (*types.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}

func NewChecker(r types.TokenResolver, tk types.TokenKey, cs map[types.TokenType]types.Checker) (c types.Checker, err error) {
	return &WrapperChecker{
		resolver: r, tokenKey: tk, checkers: cs,
	}, nil
}

func NewDefaultChecker() types.Checker {
	return &WrapperChecker{
		resolver: resolver.NewDefaultTokenResolverWithEnv(),
		tokenKey: RestTokenKey,
		checkers: map[types.TokenType]types.Checker{
			types.OAUTH2: NewTokenCheckerWithEnv(),
			types.SIGN:   NewSignCheckerWithEnv(),
		},
	}
}

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

		var keyInf = &r.Resp[types.KeyInf]{}
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
