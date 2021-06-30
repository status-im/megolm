package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/hkdf"
)

func deriveKeys(input []byte, salt []byte, info []byte) (*DerivedKeys, error) {
	h := hkdf.New(sha256.New, input, salt, info)

	keys := &DerivedKeys{
		aesKey: make([]byte, AES256_KEY_LENGTH),
		macKey: make([]byte, HMAC_KEY_LENGTH),
		aesIV:  make([]byte, AES256_IV_LENGTH),
	}

	if _, err := h.Read(keys.aesKey); err != nil {
		return nil, err
	}

	if _, err := h.Read(keys.macKey); err != nil {
		return nil, err
	}

	if _, err := h.Read(keys.aesIV); err != nil {
		return nil, err
	}

	return keys, nil
}

func pkcs7Pad(data []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("ErrInvalidBlockSize")
	}

	if data == nil || len(data) == 0 {
		return nil, errors.New("ErrInvalidPKCS7Data")
	}

	padLen := blocksize - len(data)%blocksize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)

	return append(data, padding...), nil
}

func pkcs7Unpad(data []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("ErrInvalidBlockSize")
	}

	if data == nil || len(data) == 0 {
		return nil, errors.New("ErrInvalidPKCS7Data")
	}

	if len(data)%blocksize != 0 {
		return nil, errors.New("ErrInvalidPKCS7Padding")
	}

	c := data[len(data)-1]
	n := int(c)

	if n == 0 || n > len(data) {
		return nil, errors.New("ErrInvalidPKCS7Padding")
	}

	for i := 0; i < n; i++ {
		if data[len(data)-n+i] != c {
			return nil, errors.New("ErrInvalidPKCS7Padding")
		}
	}

	return data[:len(data)-n], nil
}

func generateHMACKey(inputKey []byte) []byte {
	hmacKey := make([]byte, SHA256_BLOCK_LENGTH)
	if len(inputKey) > SHA256_BLOCK_LENGTH {
		// TODO: check this part
		h := sha256.New()
		h.Write(inputKey)
		res := h.Sum(nil)
		copy(hmacKey, res)
	} else {
		copy(hmacKey, inputKey)
	}

	return hmacKey
}

func HMACSHA256(key []byte, input []byte) []byte {
	hmacKey := generateHMACKey(key)
	ctx := hmac.New(sha256.New, hmacKey)
	ctx.Write(input)
	return ctx.Sum(nil)
}

func uvarintLen(x uint64) uint64 {
	var res uint64 = 1
	for x >= 0x80 {
		res++
		x >>= 7
	}

	return res
}

func varStringLen(n uint64) uint64 {
	return uvarintLen(n) + n
}
