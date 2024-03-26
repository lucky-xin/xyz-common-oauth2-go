package oauth2

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
	"github.com/patrickmn/go-cache"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type SignChecker struct {
	sign     Signature
	resolver TokenResolver
}

type TokenChecker struct {
	ValidMethods []string
	resolver     TokenResolver
}

func NewTokenChecker(validMethods []string, resolver TokenResolver) *TokenChecker {
	return &TokenChecker{ValidMethods: validMethods, resolver: resolver}
}

func NewTokenCheckerWithEnv() *TokenChecker {
	resolver := NewDefaultTokenResolverWithEnv()
	return &TokenChecker{
		ValidMethods: env.GetStringArray("OAUTH2_JWT_VALID_METHODS", []string{"HS512"}),
		resolver:     resolver,
	}
}

func NewSignCheckerWithEnv() *SignChecker {
	signature := NewRestConfigSignatureWithEnv()
	resolver := NewDefaultTokenResolverWithEnv()
	return &SignChecker{
		sign:     signature,
		resolver: resolver,
	}
}

func NewRestSignChecker(encryptionConfUrl string, resolver TokenResolver) *SignChecker {
	signature := NewRestConfigSignature(encryptionConfUrl)
	return &SignChecker{
		sign:     signature,
		resolver: resolver,
	}
}

func NewSignChecker(confSvc EncryptionInfSvc, resolver TokenResolver) *SignChecker {
	signature := NewSignature(confSvc)
	return &SignChecker{
		sign:     signature,
		resolver: resolver,
	}
}

func (checker *SignChecker) TokenResolver() TokenResolver {
	return checker.resolver
}

func (checker *SignChecker) Check(key []byte, token *Token) (*XyzClaims, error) {
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
			return &XyzClaims{
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

func (checker *SignChecker) CheckWithContext(key []byte, c *gin.Context) (*XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}

func (checker *TokenChecker) Check(key []byte, token *Token) (*XyzClaims, error) {
	claims := &XyzClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(checker.ValidMethods),
		jwt.WithoutClaimsValidation(),
	)
	if _, err := parser.ParseWithClaims(token.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}); err == nil {
		return claims, nil
	} else {
		return nil, err
	}
}

func (checker *TokenChecker) TokenResolver() TokenResolver {
	return checker.resolver
}

func (checker *TokenChecker) CheckWithContext(key []byte, c *gin.Context) (*XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}

type WrapperChecker struct {
	resolver TokenResolver
	tokenKey TokenKey
	checkers map[TokenType]Checker
}

func NewChecker(r TokenResolver, tk TokenKey, cs map[TokenType]Checker) (Checker, error) {
	return &WrapperChecker{
		resolver: r, tokenKey: tk, checkers: cs,
	}, nil
}

func NewDefaultChecker() Checker {
	resolver := NewDefaultTokenResolverWithEnv()
	return &WrapperChecker{
		resolver: resolver,
		tokenKey: RestTokenKey,
		checkers: map[TokenType]Checker{
			OAUTH2: NewTokenCheckerWithEnv(),
			SIGN:   NewSignCheckerWithEnv(),
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
		c.Set(cacheKey, byts, 24*time.Hour)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}

func (checker *WrapperChecker) Authorize() gin.HandlerFunc {
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

func (checker *WrapperChecker) TokenResolver() TokenResolver {
	return checker.resolver
}

func (checker *WrapperChecker) Check(key []byte, token *Token) (u *XyzClaims, err error) {
	delegate := checker.checkers[token.Type]
	if delegate == nil {
		err = errors.New(string("unsupported token type:" + token.Type))
		return
	}
	return delegate.Check(key, token)
}

func (checker *WrapperChecker) CheckWithContext(key []byte, c *gin.Context) (*XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}

// CreateToken 生成jwt
func CreateToken(tk []byte, claims *XyzClaims) (t string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	//使用指定的secret签名并获得完成的编码后的字符串token
	return token.SignedString(tk)
}
