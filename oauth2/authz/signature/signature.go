package signature

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	osign "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
)

type Checker struct {
	sign       authz.Signature
	resolver   resolver.TokenResolver
	detailsSvc authz.UserDetailsSvc
	encryptSvc conf.EncryptInfSvc
}

func CreateWithEnv() *Checker {
	return Create(osign.CreateWithEnv(), details.CreateWithEnv(), conf.CreateWithEnv(), resolver.CreateWithEnv())
}

func Create(signature authz.Signature,
	detailsSvc authz.UserDetailsSvc,
	encryptSvc conf.EncryptInfSvc,
	resolver resolver.TokenResolver) *Checker {
	return &Checker{
		sign:       signature,
		resolver:   resolver,
		detailsSvc: detailsSvc,
		encryptSvc: encryptSvc,
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (details *oauth2.UserDetails, err error) {
	return checker.sign.Check(token)
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.UserDetails, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}
