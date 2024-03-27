package oauth2

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

var (
	OAUTH2 TokenType = "OAuth2"
	SIGN   TokenType = "Signature"
)

type Token struct {
	Type   TokenType              `json:"type" binding:"required"`
	Value  string                 `json:"value" binding:"required"`
	Params map[string]interface{} `json:"params" binding:"required"`
}
type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

type KeyInf struct {
	Id  string `json:"id" binding:"required"`
	Key string `json:"key" binding:"required"`
	Alg string `json:"alg" binding:"required"`
}

type EncryptionInf struct {
	AppId     string `json:"appId" binding:"required"`
	AppSecret string `json:"appSecret" binding:"required"`
	AESKey    string `json:"aesKey" binding:"required"`
	AESIv     string `json:"aesIv" binding:"required"`
	TenantId  int32  `json:"tenantId" binding:"required"`
	Username  string `json:"username" binding:"required"`
	UserId    int64  `json:"userId" binding:"required"`
}
