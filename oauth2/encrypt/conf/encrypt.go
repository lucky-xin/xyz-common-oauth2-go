package conf

import (
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
)

// EncryptInfSvc 密钥信息接口
type EncryptInfSvc interface {
	// GetEncryptInf 获取密钥信息
	GetEncryptInf(appId string) (*oauth2.EncryptionInf, error)
}
