package oauth2

import (
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"log"
	"strings"
)

type DefaultTokenResolver struct {
	paramTokenName string
	tokenType      TokenType
}

func (d DefaultTokenResolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d DefaultTokenResolver) TokenType() TokenType {
	return d.tokenType
}

func (d DefaultTokenResolver) Resolve(c *gin.Context) *Token {
	prefixOAuth2 := d.tokenType
	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		log.Print("access token from header")
		return &Token{Type: prefixOAuth2, Value: strings.TrimSpace(authorization[len(string(prefixOAuth2)):])}
	}

	token := c.Query(d.paramTokenName)
	if token != "" {
		log.Print("access token from query")
		tmp := strings.TrimSpace(token)
		split := strings.Split(tmp, " ")
		if len(split) == 2 {
			return &Token{Type: TokenType(strings.TrimSpace(split[0])), Value: strings.TrimSpace(split[1])}
		}

		return &Token{Type: OAUTH2, Value: strings.TrimSpace(split[0])}
	}
	return nil
}

func NewDefaultTokenResolver() TokenResolver {
	return &DefaultTokenResolver{
		paramTokenName: env.GetString("OAUTH2_URI_PARAM_TOKEN_NAME", "authz"),
		tokenType:      TokenType(env.GetString("OAUTH2_TOKEN_TYPE", "OAuth2")),
	}
}
