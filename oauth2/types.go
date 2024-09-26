package oauth2

import (
	"errors"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

var (
	OAUTH2             TokenType = "OAuth2"
	SIGN               TokenType = "Signature"
	INTRO              TokenType = "INTRO"
	AppFieldName                 = "App-Id"
	TimestampFieldName           = "Timestamp"
)

func (m *TokenType) MarshalBinary() ([]byte, error) {
	return []byte(*m), nil
}

func (m *TokenType) UnmarshalBinary(data []byte) error {
	*m = TokenType(data)
	if m == nil {
		return errors.New("invalid token type")
	}
	return nil
}

// Token 信息
type Token struct {
	// Type Token类型
	Type TokenType `json:"type" binding:"required" redis:"type"`
	// Token值
	Value string `json:"value" binding:"required" redis:"value"`
	// 租户id
	Tid int64 `json:"tid" binding:"tid" redis:"tid"`
	// 用户id
	Uid int64 `json:"uid" binding:"required" redis:"uid"`
	// 用户名称
	Uname string `json:"uname" binding:"uname" redis:"uname"`
	// 扩展参数
	Params map[string]string `json:"params" binding:"required" redis:"params"`
}

func (m *Token) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

func (m *Token) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, m)
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
	// SM2 私钥
	SM2PrivateKey string `json:"sm2PrivateKey" binding:"required"`
	// SM2 公钥
	SM2PublicKey string `json:"sm2PublicKey" binding:"required"`
	// 租户id
	TenantId int32 `json:"tenantId" binding:"required"`
	// 用户名称
	Username string `json:"username" binding:"required"`
	// 用户id
	UserId int64 `json:"userId" binding:"required"`
}
