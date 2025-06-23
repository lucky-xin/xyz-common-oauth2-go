package authz

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
)

// Checker token校验器接口
type Checker interface {
	// GetTokenResolver 获取token解析器
	GetTokenResolver() resolver.TokenResolver
	// Check 校验token
	Check(key []byte, token *oauth2.Token) (*oauth2.UserDetails, error)
	// CheckWithContext 校验token，从Context之中获取token，并校验
	CheckWithContext(key []byte, c *gin.Context) (*oauth2.UserDetails, error)
}

// Signature 数字签名接口
type Signature interface {
	// CreateSign 新建数字签名
	CreateSign(params map[string]string, appSecret, timestamp string) (string, string, error)
	// Check 检验数字签名
	Check(token *oauth2.Token) (*oauth2.UserDetails, error)
}

// TokenKeySvc JWT token key接口
type TokenKeySvc interface {
	GetTokenKey() (byts []byte, err error)
}

// UserDetailsSvc 用户详情服务接口
type UserDetailsSvc interface {
	Get(username string) (details *oauth2.UserDetails, err error)
}
