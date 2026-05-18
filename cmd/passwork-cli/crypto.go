package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const openSSLSaltedPrefix = "Salted__"

func decodeBase64(s string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

var (
	stdBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	cusBase32Alphabet = "0123456789abcdefghjkmnpqrtuvwxyz"
)

func customBase32Decode(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "o", "0")
	s = strings.ReplaceAll(s, "i", "1")
	s = strings.ReplaceAll(s, "l", "1")
	s = strings.ReplaceAll(s, "s", "5")
	var b strings.Builder
	for _, r := range s {
		idx := strings.IndexRune(cusBase32Alphabet, r)
		if idx < 0 {
			continue
		}
		b.WriteByte(stdBase32Alphabet[idx])
	}
	padded := b.String()
	if n := len(padded) % 8; n != 0 {
		padded += strings.Repeat("=", 8-n)
	}
	enc := base32.NewEncoding(stdBase32Alphabet).WithPadding(base32.StdPadding)
	return enc.DecodeString(padded)
}

func evpBytesToKeyMD5(password, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var data []byte
	var block []byte
	for len(data) < keyLen+ivLen {
		h := md5.New()
		h.Write(block)
		h.Write(password)
		h.Write(salt)
		block = h.Sum(nil)
		data = append(data, block...)
	}
	return data[:keyLen], data[keyLen : keyLen+ivLen]
}

func decryptAESOpenSSL(ciphertext, password []byte) ([]byte, error) {
	if len(ciphertext) < len(openSSLSaltedPrefix)+8 {
		return nil, errors.New("ciphertext too short for OpenSSL salted format")
	}
	if string(ciphertext[:len(openSSLSaltedPrefix)]) != openSSLSaltedPrefix {
		return nil, errors.New("ciphertext does not start with Salted__")
	}
	salt := ciphertext[len(openSSLSaltedPrefix) : len(openSSLSaltedPrefix)+8]
	raw := ciphertext[len(openSSLSaltedPrefix)+8:]
	if len(raw)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length not multiple of block size")
	}
	key, iv := evpBytesToKeyMD5(password, salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(raw))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, raw)
	plain, err = unpadPKCS7(plain)
	if err != nil {
		return nil, fmt.Errorf("unpad: %w", err)
	}
	return plain, nil
}

func padPKCS7(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	if n == 0 {
		n = blockSize
	}
	padded := make([]byte, len(b)+n)
	copy(padded, b)
	for i := len(b); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func unpadPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty block")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-1-i] != byte(n) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return b[:len(b)-n], nil
}

func encryptAESOpenSSL(plain, password []byte) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand salt: %w", err)
	}
	key, iv := evpBytesToKeyMD5(password, salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := padPKCS7(plain, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	out := make([]byte, 0, len(openSSLSaltedPrefix)+8+len(ciphertext))
	out = append(out, openSSLSaltedPrefix...)
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
}

func customBase32Encode(data []byte) string {
	enc := base32.NewEncoding(stdBase32Alphabet).WithPadding(base32.StdPadding)
	encoded := enc.EncodeToString(data)
	var b strings.Builder
	for _, r := range encoded {
		if r == '=' {
			continue
		}
		idx := strings.IndexRune(stdBase32Alphabet, r)
		if idx >= 0 && idx < len(cusBase32Alphabet) {
			b.WriteByte(cusBase32Alphabet[idx])
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func encryptWithAESMasterKey(plain []byte, masterKey []byte) (string, error) {
	ciphertext, err := encryptAESOpenSSL(plain, masterKey)
	if err != nil {
		return "", fmt.Errorf("aes encrypt: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(ciphertext)
	return customBase32Encode([]byte(b64)), nil
}

func decryptWithAESMasterKey(encryptedCustomBase32 string, masterKey []byte) ([]byte, error) {
	decoded, err := customBase32Decode(encryptedCustomBase32)
	if err != nil {
		return nil, fmt.Errorf("custom base32: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return nil, fmt.Errorf("base64 after custom base32: %w", err)
	}
	plain, err := decryptAESOpenSSL(ciphertext, masterKey)
	if err != nil {
		return nil, fmt.Errorf("aes decrypt: %w", err)
	}
	return plain, nil
}

func DecryptVaultMasterKey(encryptedBase64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("vault key base64: %w", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("vault key rsa decrypt: %w", err)
	}
	return plain, nil
}

func ParsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return priv, nil
}

func ParsePublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}

func EncryptVaultMasterKey(plain []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plain, nil)
	if err != nil {
		return nil, fmt.Errorf("vault key rsa encrypt: %w", err)
	}
	return ciphertext, nil
}

func GenerateRSAKeypairAndEncryptPrivate(masterKey []byte) (publicPEM []byte, privateEncrypted string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate RSA: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	privateEncrypted, err = encryptWithAESMasterKey(privPEM, masterKey)
	if err != nil {
		return nil, "", err
	}
	return pubPEM, privateEncrypted, nil
}
