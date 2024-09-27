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
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
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
	checkTokenUrl  string
	clientId       string
	clientSecret   string
	claimKeyJp     string
	resolver       resolver.TokenResolver
	userDetailsSvc authz.UserDetailsSvc
}

func CreateWithEnv() *Checker {
	return &Checker{
		checkTokenUrl:  env.GetString("OAUTH2_CHECK_TOKEN_ENDPOINT", ""),
		clientId:       env.GetString("OAUTH2_CLIENT_ID", ""),
		clientSecret:   env.GetString("OAUTH2_CLIENT_SECRET", ""),
		claimKeyJp:     env.GetString("OAUTH2_CLAIMS_KEY_JP", "$.data"),
		resolver:       resolver.CreateWithEnv(),
		userDetailsSvc: details.CreateWithEnv(),
	}
}

func Create(checkTokenUrl, clientId, clientSecret, claimKeyJp string,
	userDetailsSvc authz.UserDetailsSvc) *Checker {
	return &Checker{
		checkTokenUrl:  checkTokenUrl,
		clientId:       clientId,
		clientSecret:   clientSecret,
		claimKeyJp:     claimKeyJp,
		resolver:       resolver.CreateWithEnv(),
		userDetailsSvc: userDetailsSvc,
	}
}

func (checker *Checker) GetTokenResolver() resolver.TokenResolver {
	return checker.resolver
}

func (checker *Checker) Check(key []byte, token *oauth2.Token) (u *oauth2.UserDetails, err error) {
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
	u = &oauth2.UserDetails{}
	origClaims := c.(map[string]interface{})
	username := collutil.StrVal(origClaims, "username", "")
	u, err = checker.userDetailsSvc.Get(username)
	if err != nil {
		return
	}
	exp := origClaims["exp"]
	if exp != nil {
		u.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp.(float64)), 0))
	}
	nbf := origClaims["nbf"]
	if nbf != nil {
		u.NotBefore = jwt.NewNumericDate(time.Unix(int64(nbf.(float64)), 0))
	}
	iat := origClaims["iat"]
	if iat != nil {
		u.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat.(float64)), 0))
	}
	return
}

func (checker *Checker) CheckWithContext(key []byte, c *gin.Context) (*oauth2.UserDetails, error) {
	t, err := checker.resolver.Resolve(c)
	if err != nil {
		return nil, err
	}
	return checker.Check(key, t)
}
