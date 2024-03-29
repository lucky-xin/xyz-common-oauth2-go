package oauth2

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

var (
	OAUTH2 TokenType = "OAuth2"
	SIGN   TokenType = "Signature"
)

// Token 信息
type Token struct {
	// Type Token类型
	Type TokenType `json:"type" binding:"required"`
	// Token值
	Value string `json:"value" binding:"required"`
	// 租户id
	Tid int64 `json:"tid" binding:"tid"`
	// 用户id
	Uid int64 `json:"uid" binding:"required"`
	// 用户名称
	Uname string `json:"uname" binding:"uname"`
	// 扩展参数
	Params map[string]interface{} `json:"params" binding:"required"`
}

// XyzClaims 自定义JWT claims
type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

// KeyInf JWT解析key
type KeyInf struct {
	Id  string `json:"id" binding:"required"`
	Key string `json:"key" binding:"required"`
	Alg string `json:"alg" binding:"required"`
}

// EncryptionInf AES加密配置信息
type EncryptionInf struct {
	// APP id
	AppId string `json:"appId" binding:"required"`
	// APP Secret
	AppSecret string `json:"appSecret" binding:"required"`
	// 获取Token key时，AES加密key
	AESKey string `json:"aesKey" binding:"required"`
	// 获取Token key时，AES加密iv
	AESIv string `json:"aesIv" binding:"required"`
	// 租户id
	TenantId int32 `json:"tenantId" binding:"required"`
	// 用户名称
	Username string `json:"username" binding:"required"`
	// 用户id
	UserId int64 `json:"userId" binding:"required"`
}
