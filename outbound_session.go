package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

const (
	ED25519_RANDOM_LENGTH      = 32
	ED25519_PUBLIC_KEY_LENGTH  = 32
	ED25519_PRIVATE_KEY_LENGTH = 64
	ED25519_SIGNATURE_LENGTH   = 64
	GROUP_MESSAGE_INDEX_TAG    = 010
	GROUP_CIPHERTEXT_TAG       = 022
	MAC_LEN                    = 8
)

type OutboundSession struct {
	Ratchet    *Megolm
	SigningKey *ed25519.PrivateKey
}

func NewOutboundSession(initialData []byte, initialCounter int) (*OutboundSession, error) {
	if len(initialData) < MEGOLM_RATCHET_LENGTH+ED25519_RANDOM_LENGTH {
		return nil, fmt.Errorf("initialData must be MEGOLM_RATCHET_LENGTH + ED25519_RANDOM_LENGTH = %d bytes. Got %d.", MEGOLM_RATCHET_LENGTH+ED25519_RANDOM_LENGTH, len(initialData))
	}

	ratchet, err := NewMegolm(initialData[:MEGOLM_RATCHET_LENGTH], initialCounter)
	if err != nil {
		return nil, err
	}

	seed := initialData[MEGOLM_RATCHET_LENGTH : MEGOLM_RATCHET_LENGTH+ED25519_RANDOM_LENGTH]
	privKey := ed25519.NewKeyFromSeed(seed)

	return &OutboundSession{
		Ratchet:    ratchet,
		SigningKey: &privKey,
	}, nil
}

func (s *OutboundSession) GenerateSessionKey() []byte {
	key := make([]byte, 1+4+MEGOLM_RATCHET_LENGTH+ED25519_PUBLIC_KEY_LENGTH+ED25519_SIGNATURE_LENGTH)

	key[0] = SESSION_KEY_VERSION

	counter := uint32(s.Ratchet.counter)
	for i := 0; i < 4; i++ {
		value := 0xFF & (counter >> 24)
		binary.BigEndian.PutUint32(key[i*4+1:], value)
		counter <<= 8
	}

	copy(key[5:], s.Ratchet.Data())
	copy(key[5+MEGOLM_RATCHET_LENGTH:], s.SigningKey.Public().(ed25519.PublicKey))

	sig := ed25519.Sign(*s.SigningKey, key[0:5+MEGOLM_RATCHET_LENGTH+ED25519_PUBLIC_KEY_LENGTH])
	copy(key[5+MEGOLM_RATCHET_LENGTH+ED25519_PUBLIC_KEY_LENGTH:], sig)

	return key
}

func (s *OutboundSession) Encrypt(plaintext []byte) ([]byte, error) {
	derivedKeys, err := deriveKeys(s.Ratchet.Data(), []byte{}, MEGOLM_KDF_INFO)
	if err != nil {
		return nil, err
	}

	ciphertextLen := len(plaintext) + aes.BlockSize - len(plaintext)%aes.BlockSize
	ciphertextEncodedLen := varStringLen(uint64(ciphertextLen))
	encodedLen :=
		uvarintLen(OLM_PROTOCOL_VERSION) +
			1 + // MESSAGE_INDEX_TAG
			uvarintLen(uint64(s.Ratchet.counter)) +
			1 + // MESSAGE_CIPHERTEXT_TAG
			ciphertextEncodedLen +
			uint64(MAC_LEN) +
			ED25519_SIGNATURE_LENGTH

	encoded := make([]byte, encodedLen)
	pos := 0
	pos += binary.PutUvarint(encoded[pos:], OLM_PROTOCOL_VERSION)
	pos += binary.PutUvarint(encoded[pos:], MESSAGE_INDEX_TAG)
	pos += binary.PutUvarint(encoded[pos:], uint64(s.Ratchet.counter))
	pos += binary.PutUvarint(encoded[pos:], MESSAGE_CIPHERTEXT_TAG)
	pos += binary.PutUvarint(encoded[pos:], uint64(ciphertextLen))

	block, err := aes.NewCipher(derivedKeys.aesKey)
	if err != nil {
		return nil, err
	}

	paddedPlaintext, err := pkcs7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext)+aes.BlockSize-len(plaintext)%aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, derivedKeys.aesIV)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	copy(encoded[pos:], ciphertext)
	pos += len(ciphertext)

	mac := HMACSHA256(derivedKeys.macKey, encoded[0:pos])
	copy(encoded[pos:pos+MAC_LEN], mac[0:MAC_LEN])
	pos += MAC_LEN

	sig := ed25519.Sign(*s.SigningKey, encoded[0:pos])
	copy(encoded[pos:], sig)

	s.Ratchet.Advance()

	return encoded, nil
}
