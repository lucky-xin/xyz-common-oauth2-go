package oauth2

import (
	"errors"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

var (
	OAUTH2                    TokenType = "OAuth2"
	SIGN                      TokenType = "Signature"
	INTRO                     TokenType = "INTRO"
	APP_ID_HEADER_NAME                  = "App-Id"
	TIMESTAMP_HEADER_NAME               = "Timestamp"
	AUTHORIZATION_PARAM_NAME            = "authz"
	AUTHORIZATION_HEADER_NAME           = "Authorization"
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
	Type TokenType `json:"type" redis:"type"`
	// Token值
	AccessToken string `json:"access_token" redis:"value"`
	// 刷新token
	RefreshToken string `json:"refresh_token" redis:"refresh_token"`
	// Token scope
	Scope string `json:"scope" redis:"scope"`
	// token有效期
	ExpiresIn int `json:"expires_in" redis:"expires_in"`
	// 扩展参数
	Params map[string]string `json:"params" redis:"params"`
}

func (m *Token) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

func (m *Token) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, m)
}

func (m *Token) AuthorizationHeader() string {
	return string(m.Type) + " " + m.AccessToken
}

// XyzClaims 自定义JWT claims
type XyzClaims struct {
	jwt.RegisteredClaims
	Username string `json:"username" binding:"required"`
	TenantId int32  `json:"tenant_id" binding:"required"`
	UserId   int64  `json:"id" binding:"required"`
}

type UserDetails struct {
	Id          int64  `json:"id"`
	TenantId    int32  `json:"tenantId"`
	Username    string `json:"username"`
	Alias       string `json:"alias"`
	Authorities []struct {
		Authorities int64  `json:"authorities"`
		Authority   string `json:"authority"`
	} `json:"authorities"`
	DeptId    int64   `json:"deptId"`
	RoleIds   []int64 `json:"roleIds"`
	RoleTypes []int64 `json:"roleTypes"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}

// KeyInf JWT解析key
type KeyInf struct {
	Id  string `json:"id" binding:"required"`
	Key string `json:"key" binding:"required"`
	Alg string `json:"alg" binding:"required"`
}

// EncryptionInf 加密配置信息
type EncryptionInf struct {
	// APP id
	AppId string `json:"appId" binding:"required"`
	// APP Secret
	AppSecret string `json:"appSecret" binding:"required"`
	// SM2 私钥
	SM2PrivateKey []byte `json:"sm2PrivateKey" binding:"required"`
	// SM2 公钥
	SM2PublicKey []byte `json:"sm2PublicKey" binding:"required"`
	// 租户id
	TenantId int32 `json:"tenantId" binding:"required"`
	// 用户名称
	Username string `json:"username" binding:"required"`
}

func (details *UserDetails) MarshalBinary() (data []byte, err error) {
	return json.Marshal(details)
}

func (details *UserDetails) UnmarshalBinary(data []byte) (err error) {
	return json.Unmarshal(data, details)
}
