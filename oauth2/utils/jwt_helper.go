package utils

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
)

// CreateToken 生成jwt
func CreateToken(tk []byte, claims *types.XyzClaims) (t string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	//使用指定的secret签名并获得完成的编码后的字符串token
	return token.SignedString(tk)
}
