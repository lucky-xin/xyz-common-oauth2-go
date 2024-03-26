package oauth2

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"log"
	"strings"
)

type DefaultTokenResolver struct {
	paramTokenName string
	tokenTypes     []TokenType
}

func (d DefaultTokenResolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d DefaultTokenResolver) Resolve(c *gin.Context) *Token {
	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		log.Print("access token from header")
		return d.Parse(authorization, c)
	}
	token := c.Query(d.paramTokenName)
	if token != "" {
		log.Print("access token from query")
		return d.Parse(authorization, c)
	}
	return nil
}

func (d DefaultTokenResolver) Parse(authorization string, c *gin.Context) *Token {
	split := strings.Split(authorization, " ")
	if len(split) == 2 {
		tt := TokenType(strings.TrimSpace(split[0]))
		t := &Token{Type: tt, Value: strings.TrimSpace(split[1])}
		if tt == SIGN {
			appId := c.GetHeader("App-Id")
			timestamp := c.GetHeader("Timestamp")
			t.Params = map[string]interface{}{
				"App-Id":    appId,
				"Timestamp": timestamp,
			}
		}
		return t
	}
	return &Token{Type: OAUTH2, Value: strings.TrimSpace(split[0])}
}

func NewDefaultTokenResolver(paramTokenName string, tokenTypes []TokenType) TokenResolver {
	return &DefaultTokenResolver{
		paramTokenName: paramTokenName,
		tokenTypes:     tokenTypes,
	}
}

func NewDefaultTokenResolverWithEnv() TokenResolver {
	array := env.GetStringArray("OAUTH2_TOKEN_TYPE", []string{"OAUTH2", "SIGN"})
	var tokenTypes []TokenType
	for i := range array {
		item := array[i]
		tokenTypes = append(tokenTypes, TokenType(item))
	}
	return &DefaultTokenResolver{
		paramTokenName: env.GetString("OAUTH2_URI_PARAM_TOKEN_NAME", "authz"),
		tokenTypes:     tokenTypes,
	}
}
