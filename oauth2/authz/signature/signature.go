package signature

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	osign "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"strings"
	"time"
)

type Checker struct {
	sign       *osign.Signature
	resolver   resolver.TokenResolver
	detailsSvc authz.UserDetailsSvc
	encryptSvc conf.EncryptInfSvc
}

func CreateWithEnv() *Checker {
	signature := osign.CreateWithEnv()
	return Create(signature, details.CreateWithEnv(), conf.CreateWithEnv(), resolver.CreateWithEnv())
}

func Create(
	signature *osign.Signature,
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
	reqAppId := token.Params[oauth2.APP_ID_HEADER_NAME]
	reqTimestamp := token.Params[oauth2.TIMESTAMP_HEADER_NAME]
	if inf, err := checker.encryptSvc.GetEncryptInf(reqAppId); err == nil {
		appSecret := inf.AppSecret
		if _, sgn, err := checker.sign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.AccessToken) != 0 {
				return nil, errors.New("invalid signature")
			}
			details, err = checker.detailsSvc.Get(inf.Username)
			if err != nil {
				return nil, err
			}
			details.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * 10))
			details.NotBefore = jwt.NewNumericDate(time.Now())
			details.IssuedAt = jwt.NewNumericDate(time.Now())
			return details, nil
		}
	} else {
		return nil, err
	}
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.UserDetails, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}
