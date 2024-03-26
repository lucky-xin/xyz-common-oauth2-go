package authz

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
)

type JWTChecker struct {
	ValidMethods []string
	resolver     types.TokenResolver
}

func NewIntrospectChecker(validMethods []string, resolver types.TokenResolver) *JWTChecker {
	return &JWTChecker{ValidMethods: validMethods, resolver: resolver}
}

func NewTokenChecker(validMethods []string, resolver types.TokenResolver) *JWTChecker {
	return &JWTChecker{ValidMethods: validMethods, resolver: resolver}
}

func NewTokenCheckerWithEnv() *JWTChecker {
	return &JWTChecker{
		ValidMethods: env.GetStringArray("OAUTH2_JWT_VALID_METHODS", []string{"HS512"}),
		resolver:     resolver.NewDefaultTokenResolverWithEnv(),
	}
}

func (checker *JWTChecker) Check(key []byte, token *types.Token) (*types.XyzClaims, error) {
	claims := &types.XyzClaims{}
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

func (checker *JWTChecker) TokenResolver() types.TokenResolver {
	return checker.resolver
}

func (checker *JWTChecker) CheckWithContext(key []byte, c *gin.Context) (*types.XyzClaims, error) {
	return checker.Check(key, checker.resolver.Resolve(c))
}
