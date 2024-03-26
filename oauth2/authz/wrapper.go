package authz

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"net/http"
)

type WrapperChecker struct {
	resolver types.TokenResolver
	tokenKey types.TokenKey
	checkers map[types.TokenType]types.Checker
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

func (checker *WrapperChecker) TokenResolver() types.TokenResolver {
	return checker.resolver
}

func (checker *WrapperChecker) Check(key []byte, token *types.Token) (u *types.XyzClaims, err error) {
	delegate := checker.checkers[token.Type]
	if delegate == nil {
		err = errors.New(string("unsupported token type:" + token.Type))
		return
	}
	return delegate.Check(key, token)
}

func (checker *WrapperChecker) CheckWithContext(key []byte, c *gin.Context) (*types.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}
