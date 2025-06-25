package samples

import (
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/intro"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"testing"
)

func TestExtractIntroToken(t *testing.T) {
	checker := intro.Create("http://127.0.0.1:3000/oauth2/introspect",
		"",
		"",
		"$",
		details.CreateWithEnv(),
	)
	token := &oauth2.Token{
		Type:        oauth2.OAUTH2,
		AccessToken: "eyJraWQiOiI3ZDE5OThkNC03YmJmLTQyYTgtYWY4MC03MTAzZGQ2MjQ0ZDMiLCJhbGciOiJIUzUxMiJ9.eyJ0ZW5hbnRfaWQiOjEsInN1YiI6Imx1Y3giLCJhdWQiOiJwaXN0b25pbnRfY2xvdWQiLCJuYmYiOjE3MTE3ODE4NjgsInNjb3BlIjpbInJlYWRfd3JpdGUiXSwiaXNzIjoiaHR0cHM6Ly9kZXYtYXV0aC5zdmMucGlzdG9uaW50LmNvbSIsImlkIjozLCJleHAiOjE3MTE3ODU0NjgsImlhdCI6MTcxMTc4MTg2OCwianRpIjoicGlzdG9uaW50IiwidXNlcm5hbWUiOiJsdWN4In0.dzMidQybsSo_qPPtMcZdNuyIdvl0aBgX3HtNZrUmulvGXDEK07RHYLD4d32dJUFifKc88jtb2eLQAos84x87GQ",
	}
	u, err := checker.Check([]byte{}, token)
	if err != nil {
		panic(err)
	}
	println(u.Username)
}
