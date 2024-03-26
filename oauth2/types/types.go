package types

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

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

type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

type Token struct {
	Type   TokenType              `json:"type" binding:"required"`
	Value  string                 `json:"value" binding:"required"`
	Params map[string]interface{} `json:"params" binding:"required"`
}

type TokenType string

var (
	OAUTH2 TokenType = "OAuth2"
	SIGN   TokenType = "Signature"
)

type TokenResolver interface {
	UriParamTokenName() string
	Resolve(c *gin.Context) *Token
}

type Signature interface {
	EncryptionInfSvc() (EncryptionInfSvc, error)
	CreateSign(params map[string]interface{}, appSecret, timestamp string) (string, error)
	Check(token *Token) (*XyzClaims, error)
}

type EncryptionInfSvc interface {
	GetEncryptionInf(appId string) (*EncryptionInf, error)
}

type Checker interface {
	TokenResolver() TokenResolver
	Check(key []byte, token *Token) (*XyzClaims, error)
	CheckWithContext(key []byte, c *gin.Context) (*XyzClaims, error)
}

type TokenKey func() (byts []byte, err error)
