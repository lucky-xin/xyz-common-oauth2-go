package resolver

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"log"
	"strings"
)

type TokenResolver interface {
	UriParamTokenName() string
	Resolve(c *gin.Context) *oauth2.Token
}

type DefaultTokenResolver struct {
	paramTokenName string
	tokenTypes     []oauth2.TokenType
}

func (d DefaultTokenResolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d DefaultTokenResolver) Resolve(c *gin.Context) *oauth2.Token {
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

func (d DefaultTokenResolver) Parse(authorization string, c *gin.Context) *oauth2.Token {
	split := strings.Split(authorization, " ")
	if len(split) == 2 {
		tt := oauth2.TokenType(strings.TrimSpace(split[0]))
		t := &oauth2.Token{Type: tt, Value: strings.TrimSpace(split[1])}
		if tt == oauth2.SIGN {
			appId := c.GetHeader("App-Id")
			timestamp := c.GetHeader("Timestamp")
			t.Params = map[string]interface{}{
				"App-Id":    appId,
				"Timestamp": timestamp,
			}
		}
		return t
	}
	return &oauth2.Token{Type: oauth2.OAUTH2, Value: strings.TrimSpace(split[0])}
}

func Create(paramTokenName string, tokenTypes []oauth2.TokenType) TokenResolver {
	return &DefaultTokenResolver{
		paramTokenName: paramTokenName,
		tokenTypes:     tokenTypes,
	}
}

func CreateWithEnv() TokenResolver {
	array := env.GetStringArray("OAUTH2_TOKEN_TYPE", []string{"OAUTH2", "SIGN"})
	var tokenTypes []oauth2.TokenType
	for i := range array {
		item := array[i]
		tokenTypes = append(tokenTypes, oauth2.TokenType(item))
	}
	return &DefaultTokenResolver{
		paramTokenName: env.GetString("OAUTH2_URI_PARAM_TOKEN_NAME", "authz"),
		tokenTypes:     tokenTypes,
	}
}
