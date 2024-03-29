package signature

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	osign "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"strings"
	"time"
)

type Checker struct {
	sign     authz.Signature
	resolver resolver.TokenResolver
}

func CreateWithEnv() *Checker {
	return &Checker{
		sign:     osign.CreateWithEnv(),
		resolver: resolver.CreateWithEnv(),
	}
}

func CreateWithRest(encryptionConfUrl string, expireMs, cleanupMs time.Duration,
	resolver resolver.TokenResolver) *Checker {
	signature := osign.CreateWithRest(encryptionConfUrl, expireMs, cleanupMs)
	return &Checker{
		sign:     signature,
		resolver: resolver,
	}
}

func Create(confSvc conf.EncryptInfSvc, resolver resolver.TokenResolver) *Checker {
	signature := osign.Create(confSvc)
	return &Checker{
		sign:     signature,
		resolver: resolver,
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (*oauth2.XyzClaims, error) {
	reqAppId := token.Params["App-Id"]
	reqTimestamp := token.Params["Timestamp"]
	confSvc, err := checker.sign.GetEncryptionInfSvc()
	if err != nil {
		return nil, err
	}
	if inf, err := confSvc.GetEncryptInf(reqAppId); err != nil {
		appSecret := inf.AppSecret
		username := inf.Username
		userId := inf.UserId
		if sgn, err := checker.sign.CreateSign(token.Params, appSecret, reqTimestamp); err != nil {
			return nil, err
		} else {
			if strings.Compare(sgn, token.Value) != 0 {
				return nil, errors.New("invalid signature")
			}
			return &oauth2.XyzClaims{
				Username: username,
				UserId:   userId,
				TenantId: inf.TenantId,
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

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}
