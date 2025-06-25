package samples

import (
	"bytes"
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	xjwt "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/jwt"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/signature"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/wrapper"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/details"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
	resolver2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	sign2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"io"
	"net/http"
	"testing"
)

func TestOAUth2CliTest(tet *testing.T) {
	appId := "9c607513b605406497afc395b011xyz"
	appSecret := "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAl3xyz.xyz"
	// 获取token key
	//生成数字签名
	var timestamp, sgn string
	if appId != "" && appSecret != "" {
		timestamp, sgn = sign.SignWithTimestamp(appSecret, "")
	}
	//获取token key
	client := &http.Client{}
	url := "http://127.0.0.1:6666/oauth2/token-key"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Signature "+sgn)
	req.Header.Set(oauth2.APP_ID_HEADER_NAME, appId)
	req.Header.Set(oauth2.TIMESTAMP_HEADER_NAME, timestamp)
	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	var tokenKeyResp r.Resp[string]
	byts, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(byts, &tokenKeyResp)
	if err != nil {
		panic(err)
	}
	println("orig token key->", tokenKeyResp.Data())

	deTk := tokenKeyResp.Data()
	aesKey := "B31F2A75FBF94099B31F2A75FBF94099" // 此处16|24|32个字符
	aesIv := "1234567890123456"
	encryptor := aescbc.Encryptor{Key: aesKey, Iv: aesIv}
	tk, err := encryptor.DecryptBase64(deTk)
	if err != nil {
		panic(err)
	}
	println("plaintext token key->", string(tk))

	// 获取token
	url = "http://127.0.0.1:6666/oauth2/token"
	params := map[string]interface{}{
		"username": "chaoxin.lu",
		"password": "************",
	}

	jsonBytes, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	req, err = http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		panic(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	var tokenResp r.Resp[XyzOAuth2Token]
	byts, err = io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(byts, &tokenResp)
	if err != nil {
		panic(err)
	}
	println("access token ->", tokenResp.Data().AccessToken)

	// 解析token
	t := &oauth2.Token{Type: oauth2.OAUTH2, AccessToken: tokenResp.Data().AccessToken}
	tokenKeySvc := key.CreateWithEnv()
	resolver := resolver2.Create("oauthz", []oauth2.TokenType{oauth2.OAUTH2})
	detailsSvc := details.CreateWithEnv()
	encryptSvc := conf.CreateWithEnv()
	s := sign2.CreateWithEnv()
	checker, err := wrapper.Create(
		resolver,
		tokenKeySvc,
		map[oauth2.TokenType]authz.Checker{
			oauth2.OAUTH2: xjwt.Create([]string{"HS512"}, resolver, detailsSvc),
			oauth2.SIGN: signature.Create(
				s,
				detailsSvc,
				encryptSvc,
				resolver,
			),
		},
	)
	if err != nil {
		panic(err)
	}
	deClaims, err := checker.Check(tk, t)
	if err != nil {
		panic(err)
	}
	println(deClaims.Id)
	println(deClaims.Username)
	auth := oauth2.CreateBasicAuth("piston", "lskcjakjck")
	println(auth)
}
