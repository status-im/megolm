package main

import (
	"bytes"
	"testing"
)

func TestOutboundSession(t *testing.T) {
	randomData := []byte(
		"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF" +
			"0123456789ABDEF0123456789ABCDEF")

	o, err := NewOutboundSession(randomData, 0)
	if err != nil {
		t.Fatal(err)
	}

	sessionKey := o.GenerateSessionKey()

	expectedSessionKey := decodeHEX("020000000030313233343536373839414244454630313233343536373839414243444546303132333435363738394142444546303132333435363738394142434445463031323334353637383941424445463031323334353637383941424344454630313233343536373839414244454630313233343536373839414243444546303132330d1b760d410eae0fc7fb25068c34eaaf27fc1f5605fc1663234e07c0e55265c61b0ac599a49bf5b47f798f3180446bc663f4ee11660fdbaa036a7c3cc1dd9d5e72b2682e7c4ea82d9e7ef3f99640e5b75554e70c8967c1df281d4611ba4f1309")
	if !bytes.Equal(sessionKey, expectedSessionKey) {
		t.Fatalf("expected %x, got %x", expectedSessionKey, sessionKey)
	}

	plaintext := "Message"
	encrypted, err := o.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}

	expectedEncrytped := decodeHEX("03080012101c6e1e94a5b072a32671b9f43e87607ef171cc8e147af46f05e3eaa331a1659c85eeb09657debf0b9d13911bd4f70d715d6d5baf216acbc917e6e22f1045b7bc54fc064451b9ec1d42b66c5a9ee3fc6c7b679d8aa5c0fb03")
	if !bytes.Equal(encrypted, expectedEncrytped) {
		t.Fatalf("expected %x, got %x", expectedEncrytped, encrypted)
	}
}
