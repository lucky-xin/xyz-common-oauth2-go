package authz

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
)

type Checker interface {
	TokenResolver() resolver.TokenResolver
	Check(key []byte, token *oauth2.Token) (*oauth2.XyzClaims, error)
	CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error)
}

type Signature interface {
	EncryptionInfSvc() (EncryptionInfSvc, error)
	CreateSign(params map[string]interface{}, appSecret, timestamp string) (string, error)
	Check(token *oauth2.Token) (*oauth2.XyzClaims, error)
}

type EncryptionInfSvc interface {
	GetEncryptionInf(appId string) (*oauth2.EncryptionInf, error)
}

type TokenKey func() (byts []byte, err error)
