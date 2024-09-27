package wrapper

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	xjwt "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/jwt"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/signature"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"net/http"
	"time"
)

type Checker struct {
	resolver resolver.TokenResolver
	tokenKey authz.TokenKeySvc
	checkers map[oauth2.TokenType]authz.Checker
}

func CreateWithEnv() *Checker {
	tokenResolver := resolver.CreateWithEnv()
	checkers := map[oauth2.TokenType]authz.Checker{
		oauth2.OAUTH2: xjwt.CreateWithEnv(),
		oauth2.SIGN:   signature.CreateWithEnv(),
	}
	restTokenKey := key.Create(conf.CreateWithEnv(), 6*time.Hour)
	return &Checker{
		resolver: tokenResolver,
		tokenKey: restTokenKey,
		checkers: checkers,
	}
}

func Create(r resolver.TokenResolver,
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
