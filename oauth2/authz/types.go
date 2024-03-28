package authz

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
)

// Checker token校验器接口
type Checker interface {
	// GetTokenResolver 获取token解析器
	GetTokenResolver() resolver.TokenResolver
	// Check 校验token
	Check(key []byte, token *oauth2.Token) (*oauth2.XyzClaims, error)
	// CheckWithContext 校验token，从Context之中获取token，并校验
	CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error)
}

// Signature 数字签名接口
type Signature interface {
	// GetEncryptionInfSvc 获取数字签名密钥信息服务
	GetEncryptionInfSvc() (conf.EncryptInfSvc, error)
	// CreateSign 新建数字签名
	CreateSign(params map[string]interface{}, appSecret, timestamp string) (string, error)
	// Check 检验数字签名
	Check(token *oauth2.Token) (*oauth2.XyzClaims, error)
}

// TokenKey JWT token key接口
type TokenKey interface {
	Get() (byts []byte, err error)
}
