package intro

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/collutil"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"github.com/oliveagle/jsonpath"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Checker struct {
	checkTokenUrl string
	clientId      string
	clientSecret  string
	claimKeyJp    string
	resolver      resolver.TokenResolver
}

func CreateWithEnv() *Checker {
	return &Checker{
		checkTokenUrl: env.GetString("OAUTH2_CHECK_TOKEN_ENDPOINT", ""),
		clientId:      env.GetString("OAUTH2_CLIENT_ID", ""),
		clientSecret:  env.GetString("OAUTH2_CLIENT_SECRET", ""),
		claimKeyJp:    env.GetString("OAUTH2_CLAIMS_KEY_JP", "$.data"),
		resolver:      resolver.CreateWithEnv(),
	}
}

func Create(checkTokenUrl, clientId, clientSecret, claimKeyJp string) *Checker {
	return &Checker{
		checkTokenUrl: checkTokenUrl,
		clientId:      clientId,
		clientSecret:  clientSecret,
		claimKeyJp:    claimKeyJp,
		resolver:      resolver.CreateWithEnv(),
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (u *oauth2.XyzClaims, err error) {
	auth := oauth2.CreateBasicAuth(checker.clientId, checker.clientSecret)
	reader := strings.NewReader(fmt.Sprintf("token=%s", token.Value))
	req, err := http.NewRequest(http.MethodPost, checker.checkTokenUrl, reader)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.HttpClient.Do(req)
	if err != nil {
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("invalid token")
	}
	byts, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var res map[string]interface{}
	err = json.Unmarshal(byts, &res)
	if err != nil {
		return nil, err
	}
	c, err := jsonpath.JsonPathLookup(res, checker.claimKeyJp)
	if err != nil {
		log.Println("json path lookup failed,", err.Error())
		return
	}
	u = &oauth2.XyzClaims{
		RegisteredClaims: jwt.RegisteredClaims{},
	}
	origClaims := c.(map[string]interface{})
	u.RegisteredClaims.Issuer = collutil.StrVal(origClaims, "iss", "")
	u.RegisteredClaims.Subject = collutil.StrVal(origClaims, "sub", "")
	u.RegisteredClaims.ID = collutil.StrVal(origClaims, "jti", "")
	aud := origClaims["aud"]
	if aud != nil {
		u.RegisteredClaims.Audience = aud.([]string)
	}

	exp := origClaims["exp"]
	if exp != nil {
		u.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp.(float64)), 0))
	}

	nbf := origClaims["nbf"]
	if nbf != nil {
		u.RegisteredClaims.NotBefore = jwt.NewNumericDate(time.Unix(int64(nbf.(float64)), 0))
	}

	iat := origClaims["iat"]
	if iat != nil {
		u.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat.(float64)), 0))
	}

	u.Username = collutil.StrVal(origClaims, "username", "")
	u.UserId = collutil.Int64Val(origClaims, "user_id", 0)
	u.TenantId = collutil.Int32Val(origClaims, "tenant_id", 0)
	return
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.XyzClaims, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}
