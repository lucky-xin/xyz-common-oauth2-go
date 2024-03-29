package jwt

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
)

// Checker JWT校验器
type Checker struct {
	// 解析token校验算法
	ValidMethods []string
	// Token解析器
	resolver resolver.TokenResolver
}

// Create 新建JWT校验器
func Create(validMethods []string, resolver resolver.TokenResolver) *Checker {
	return &Checker{ValidMethods: validMethods, resolver: resolver}
}

// CreateWithEnv 根据环境变量配置新建JWT校验器
func CreateWithEnv() *Checker {
	return &Checker{
		ValidMethods: env.GetStringArray("OAUTH2_JWT_VALID_METHODS", []string{"HS512"}),
		resolver:     resolver.CreateWithEnv(),
	}
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (*oauth2.XyzClaims, error) {
	claims := &oauth2.XyzClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(checker.ValidMethods),
		jwt.WithoutClaimsValidation(),
	)
	if _, err := parser.ParseWithClaims(token.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}); err == nil {
		return claims, nil
	} else {
		return nil, err
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}

// CreateToken 生成jwt
func CreateToken(tk []byte, claims *oauth2.XyzClaims) (t string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	//使用指定的secret签名并获得完成的编码后的字符串token
	return token.SignedString(tk)
}
