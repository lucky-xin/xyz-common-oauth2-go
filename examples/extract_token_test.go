package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func getKeyBytes(key string) []byte {
	keyBytes := []byte(key)
	switch l := len(keyBytes); {
	case l < 16:
		keyBytes = append(keyBytes, make([]byte, 16-l)...)
	case l > 16:
		keyBytes = keyBytes[:16]
	}
	return keyBytes
}

func doEncrypt(key string, origData []byte) ([]byte, error) {
	keyBytes := getKeyBytes(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, keyBytes[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func doDecrypt(key, crypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AESEncrypt(key string, val string) ([]byte, error) {
	origData := []byte(val)
	crypted, err := doEncrypt(key, origData)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

func AESDecrypt(key, val []byte) ([]byte, error) {
	origData, err := doDecrypt(key, val)
	if err != nil {
		return nil, err
	}
	return origData, nil
}

func TestExtractToken(t *testing.T) {
	//token := "eyJraWQiOiJmY2Y2MDE4Ny0wOGE0LTQ4NGUtOTVmMS0wNzdhNDUzZWU3NjIiLCJhbGciOiJIUzUxMiJ9.eyJ0ZW5hbnRfaWQiOjEsInN1YiI6Imx1Y3giLCJhdWQiOiJwaXN0b25pbnRfY2xvdWQiLCJuYmYiOjE2OTM0NTc2NjIsInNjb3BlIjpbInJlYWQiXSwiaXNzIjoiaHR0cHM6Ly9kZXYtYXV0aC5zdmMucGlzdG9uaW50LmNvbSIsImlkIjozLCJleHAiOjE2OTM0NjEyNjIsImlhdCI6MTY5MzQ1NzY2MiwianRpIjoicGlzdG9uaW50IiwidXNlcm5hbWUiOiJsdWN4In0.c0hcqbt_kMHnniTQ6D4m5wj4KYi0YEyYpPJgSgpHuGLuGxpnlNMZY9SVJMt5ba9IBO09hskagPh4CQv9MPBxsw"
	//details, err := oauth2.CheckToken(token)
	//if err != nil {
	//	panic(err)
	//}
	//marshal, _ := json.Marshal(details)
	//println(string(marshal))
}
