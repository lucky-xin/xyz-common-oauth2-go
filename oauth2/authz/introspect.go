package authz

import (
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/collutil"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"io"
	"net/http"
	"time"
)

type IntrospectChecker struct {
	checkTokenUrl string
	clientId      string
	clientSecret  string
	claimKey      string
	resolver      types.TokenResolver
}

func NewIntrospectCheckerWithEnv() types.Checker {
	return &IntrospectChecker{
		checkTokenUrl: env.GetString("OAUTH2_CHECK_TOKEN_URL", ""),
		clientId:      env.GetString("OAUTH2_CLIENT_ID", ""),
		clientSecret:  env.GetString("OAUTH2_CLIENT_SECRET", ""),
		claimKey:      env.GetString("OAUTH2_RESP_CLAIMS_KEY", ""),
		resolver:      resolver.NewDefaultTokenResolverWithEnv(),
	}
}

func (checker *IntrospectChecker) TokenResolver() types.TokenResolver {
	return checker.resolver
}

func (checker *IntrospectChecker) Check(key []byte, token *types.Token) (u *types.XyzClaims, err error) {
	auth := utils.ToBasicAuth(checker.clientId, checker.clientSecret)
	if req, err := http.NewRequest("GET", checker.checkTokenUrl+"?token="+token.Value, nil); err != nil {
		return nil, err
	} else {
		req.Header.Set("Authorization", auth)
		if resp, err := utils.HttpClient.Do(req); err == nil {
			if resp.StatusCode != http.StatusOK {
				return nil, errors.New("invalid token")
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					panic(err)
				}
			}(resp.Body)
			byts, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			var res map[string]interface{}
			err = json.Unmarshal(byts, &res)
			if err != nil {
				return nil, err
			}
			origClaims := res
			if checker.claimKey != "" {
				origClaims = res[checker.claimKey].(map[string]interface{})
			}
			u = &types.XyzClaims{
				RegisteredClaims: jwt.RegisteredClaims{},
			}
			u.RegisteredClaims.Issuer = collutil.StrVal(origClaims, "iss", "")
			u.RegisteredClaims.Subject = collutil.StrVal(origClaims, "sub", "")
			u.RegisteredClaims.ID = collutil.StrVal(origClaims, "jti", "")
			aud := origClaims["aud"]
			if aud != nil {
				u.RegisteredClaims.Audience = aud.([]string)
			}

			exp := origClaims["exp"]
			if exp != nil {
				u.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Unix(exp.(int64), 0))
			}

			nbf := origClaims["nbf"]
			if nbf != nil {
				u.RegisteredClaims.NotBefore = jwt.NewNumericDate(time.Unix(nbf.(int64), 0))
			}

			iat := origClaims["iat"]
			if iat != nil {
				u.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Unix(iat.(int64), 0))
			}

			u.Username = collutil.StrVal(origClaims, "username", "")
			u.UserId = collutil.Int64Val(origClaims, "user_id", 0)
			u.TenantId = collutil.Int32Val(origClaims, "tenant_id", 0)

		} else {
			return nil, err
		}
	}
	return nil, err
}

func (checker *IntrospectChecker) CheckWithContext(key []byte, c *gin.Context) (*types.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}
