package resolver

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"log"
	"strings"
)

// TokenResolver token解析器
type TokenResolver interface {
	// UriParamTokenName 支持url传递token时，参数名称
	UriParamTokenName() string
	// Resolve 获取Context token
	Resolve(c *gin.Context) (t *oauth2.Token, err error)
}

type parse func(c *gin.Context, t *oauth2.Token) error

var parses = map[oauth2.TokenType]parse{
	oauth2.SIGN:   parseSign,
	oauth2.OAUTH2: parseOAuth2,
}

type DefaultTokenResolver struct {
	paramTokenName string
	tokenTypes     []oauth2.TokenType
}

func (d DefaultTokenResolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d DefaultTokenResolver) Resolve(c *gin.Context) (t *oauth2.Token, err error) {
	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		log.Print("access token from header")
		return d.createToken(authorization, c)
	}
	token := c.Query(d.paramTokenName)
	if token != "" {
		log.Print("access token from query")
		return d.createToken(authorization, c)
	}
	return
}

func (d DefaultTokenResolver) createToken(authorization string, c *gin.Context) (t *oauth2.Token, err error) {
	split := strings.Split(authorization, " ")
	if len(split) == 2 {
		tt := oauth2.TokenType(strings.TrimSpace(split[0]))
		t = &oauth2.Token{Type: tt, Value: strings.TrimSpace(split[1])}
		p := parses[tt]
		if p == nil {
			err = errors.New("invalid token type")
			return
		}
		err = p(c, t)
		return
	}
	t = &oauth2.Token{Type: oauth2.OAUTH2, Value: strings.TrimSpace(split[0])}
	return
}

func parseSign(c *gin.Context, t *oauth2.Token) (err error) {
	t.Params = map[string]string{}
	if c.ContentType() == "application/json" {
		err = c.BindJSON(&t.Params)
		if err != nil {
			return err
		}
	} else {
		for k, v := range c.Request.URL.Query() {
			t.Params[k] = strings.Join(v, ",")
		}
		for k, v := range c.Request.PostForm {
			t.Params[k] = strings.Join(v, ",")
		}
	}
	t.Params[oauth2.APP_ID_HEADER_NAME] = c.GetHeader(oauth2.APP_ID_HEADER_NAME)
	t.Params[oauth2.TIMESTAMP_HEADER_NAME] = c.GetHeader(oauth2.TIMESTAMP_HEADER_NAME)
	return nil
}

func parseOAuth2(c *gin.Context, t *oauth2.Token) error {
	return nil
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
