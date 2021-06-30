package main

import (
	"bytes"
	"log"
	"testing"
)

func TestInboundSession(t *testing.T) {
	sessionKey := "AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM" +
		"DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND" +
		"U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMztqJ7zOtqQtYqOo0CpvDXNlMhV3HeJ" +
		"DpjrASKGLWdop4lx1cSN3Xv1TgfLPW8rhGiW+hHiMxd36nRuxscNv9k4oJA/KP+o0mi1w" +
		"v44StrEJ1wwx9WZHBUIWkQbaBSuBDw=="

	message := "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8nP4pNZGl/3QMgrzCZPmP+F2aPLyKPz" +
		"xRPBMUkeXRJ6Iqm5NeOdx2eERgTW7P20CM+lL3Xpk+ZUOOPvsSQNaAL"

	s, err := NewInboundSession(sessionKey)
	if err != nil {
		log.Fatal(err)
	}

	m, err := s.Decrypt(message)
	if err != nil {
		log.Fatal(err)
	}

	expectedMessage := []byte("Message")
	if !bytes.Equal(m.Plaintext, expectedMessage) {
		t.Fatalf("expected message to be `%s`, got `%s`", expectedMessage, m.Plaintext)
	}
}
