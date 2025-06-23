package wrapper

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/intro"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/jwt"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/signature"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"net/http"
	"time"
)

type Checker struct {
	resolver resolver.TokenResolver
	tokenKey authz.TokenKeySvc
	checkers map[oauth2.TokenType]authz.Checker
}

func CreateWithEnv() *Checker {
	privateKeyHex := env.GetString("OAUTH2_SM2_PRIVATE_KEY", "")
	publicKeyHex := env.GetString("OAUTH2_SM2_PUBLIC_KEY", "")
	sm2, err := encryption.NewSM2(publicKeyHex, privateKeyHex)
	if err != nil {
		println(err)
	}
	signer := sign.CreateWithEnv()
	tokenResolver := resolver.CreateWithEnv()
	confExpireMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_EXPIRE_MS", 6*time.Hour.Milliseconds())
	confCleanupMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CLEANUP_MS", 6*time.Hour.Milliseconds())
	userDetailsExpireMs := env.GetInt64("OAUTH2_USER_DETAILS_EXPIRE_MS", 6*time.Hour.Milliseconds())
	tokenKeyExpireMs := env.GetInt64("OAUTH2_TOKEN_KEY_EXPIRES_MS", 6*time.Hour.Milliseconds())
	jwtValidMethods := env.GetStringArray("OAUTH2_JWT_VALID_METHODS", []string{"HS512"})

	detailsSvc := details.Create(
		time.Duration(userDetailsExpireMs)*time.Millisecond,
		sm2,
		signer,
	)
	confSvc := conf.Create(
		env.GetString("OAUTH2_ISSUER_ENDPOINT", "https://127.0.0.1:6666")+"/oauth2/encryption/config",
		sm2,
		time.Duration(confExpireMs)*time.Millisecond,
		time.Duration(confCleanupMs)*time.Millisecond,
	)

	jwtChecker := jwt.Create(
		jwtValidMethods,
		tokenResolver,
		detailsSvc,
	)
	signChecker := signature.Create(
		signer,
		detailsSvc,
		confSvc,
		tokenResolver,
	)
	introChecker := intro.CreateWithEnv()
	checkers := map[oauth2.TokenType]authz.Checker{
		oauth2.OAUTH2: jwtChecker,
		oauth2.SIGN:   signChecker,
		oauth2.INTRO:  introChecker,
	}

	restTokenKey := key.Create(
		confSvc,
		signer,
		sm2,
		time.Duration(tokenKeyExpireMs)*time.Millisecond,
	)
	return &Checker{
		resolver: tokenResolver,
		tokenKey: restTokenKey,
		checkers: checkers,
	}
}

func Create(
	r resolver.TokenResolver,
	tk authz.TokenKeySvc,
	cs map[oauth2.TokenType]authz.Checker) (c *Checker, err error) {
	return &Checker{
		resolver: r, tokenKey: tk, checkers: cs,
	}, nil
}

func (checker *Checker) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenKey := key.CreateWithEnv()
		byts, err := tokenKey.GetTokenKey()
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
		c.Set("uid", verify.Id)
		c.Set("uname", verify.Username)
		c.Set("tid", verify.TenantId)
		c.Next()
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (u *oauth2.UserDetails, err error) {
	delegate := checker.checkers[token.Type]
	if delegate == nil {
		err = errors.New(string("unsupported token type:" + token.Type))
		return
	}
	return delegate.Check(key, token)
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.UserDetails, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}
