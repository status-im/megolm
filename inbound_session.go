package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	AES256_KEY_LENGTH      = 32
	AES256_IV_LENGTH       = 16
	HMAC_KEY_LENGTH        = 32
	HKDF_DEFAULT_SALT_LEN  = 32
	SESSION_SHARING_LENGTH = 229
	SESSION_KEY_VERSION    = 2

	MESSAGE_INDEX_TAG      = 0x08
	MESSAGE_CIPHERTEXT_TAG = 0x12
)

var MEGOLM_KDF_INFO = []byte("MEGOLM_KEYS")

type Message struct {
	Version   byte
	Payload   []byte
	Index     int
	Plaintext []byte
	MAC       []byte
	Signature []byte
}

type DerivedKeys struct {
	aesKey []byte
	macKey []byte
	aesIV  []byte
}

type InboundSession struct {
	Version        byte
	SigningPubKey  []byte
	InitialRatchet *Megolm
	LatestRatchet  *Megolm
}

func NewInboundSession(encodedSession string) (*InboundSession, error) {
	session, err := base64.StdEncoding.DecodeString(encodedSession)
	if err != nil {
		return nil, err
	}

	if len(session) != SESSION_SHARING_LENGTH {
		return nil, errors.New("bad session length")
	}

	version := session[0]
	index := int(binary.BigEndian.Uint32(session[1:5]))
	ratchets := session[5:133]
	signingPubKey := session[133:165]
	signature := session[165:229]

	initialRatchet, err := NewMegolm(ratchets, index)
	if err != nil {
		return nil, err
	}

	latestRatchet, err := NewMegolm(ratchets, index)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(signingPubKey, session[0:165], signature) {
		return nil, errors.New("bad signature")
	}

	return &InboundSession{
		Version:        version,
		SigningPubKey:  signingPubKey,
		InitialRatchet: initialRatchet,
		LatestRatchet:  latestRatchet,
	}, nil
}

func (s *InboundSession) Decrypt(rawMessage string) (*Message, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawMessage)
	if err != nil {
		return nil, err
	}

	// 1 (version) + n (payload) + 8 (MAC) + 72 (signature)
	// TODO: it should be min 81 + min message len
	if len(decoded) < 81 {
		return nil, errors.New("message too short")
	}

	// TODO: check max length
	msgLen := len(decoded)

	version := decoded[0]
	payload := decoded[1 : msgLen-72]
	mac := decoded[msgLen-72 : msgLen]
	signature := decoded[msgLen-64 : msgLen]

	index, ciphertext, err := decodeMessage(payload)
	if err != nil {
		return nil, err
	}

	message := decoded[0 : msgLen-64]
	if !ed25519.Verify(s.SigningPubKey, message, signature) {
		return nil, errors.New("bad signature")
	}

	// TODO: advance ratchet to index
	derivedKeys, err := deriveKeys(s.LatestRatchet.Data(), []byte{}, MEGOLM_KDF_INFO)
	if err != nil {
		return nil, err
	}

	// TODO: check mac
	block, err := aes.NewCipher(derivedKeys.aesKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, derivedKeys.aesIV)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, _ = pkcs7Unpad(ciphertext, aes.BlockSize)

	return &Message{
		Version:   version,
		Payload:   payload,
		Index:     index,
		Plaintext: ciphertext,
		MAC:       mac,
		Signature: signature,
	}, nil
}

//TODO: check megolm encoding implementation
func decodeMessage(payload []byte) (int, []byte, error) {
	buf := bytes.NewBuffer(payload)
	tag, err := binary.ReadUvarint(buf)
	if err != nil {
		return 0, nil, err
	}

	if tag != MESSAGE_INDEX_TAG {
		return 0, nil, fmt.Errorf("expected tag %x, got %x", MESSAGE_INDEX_TAG, tag)
	}

	index, err := binary.ReadUvarint(buf)
	if err != nil {
		return 0, nil, err
	}

	tag, err = binary.ReadUvarint(buf)
	if err != nil {
		return 0, nil, err
	}

	if tag != MESSAGE_CIPHERTEXT_TAG {
		return 0, nil, fmt.Errorf("expected tag %x, got %x", MESSAGE_CIPHERTEXT_TAG, tag)
	}

	length, err := binary.ReadUvarint(buf)
	if err != nil {
		return 0, nil, err
	}

	ciphertext := make([]byte, length)
	n, err := buf.Read(ciphertext)
	if err != nil {
		return 0, nil, err
	}

	if n != int(length) {
		return 0, nil, fmt.Errorf("expected cipertext length %d, got %d", length, n)
	}

	return int(index), ciphertext, nil
}
