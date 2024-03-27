package conf

import (
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
)

type EncryptInfSvc interface {
	GetEncryptInf(appId string) (*oauth2.EncryptionInf, error)
}
