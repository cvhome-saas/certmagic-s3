package s3

import (
	"bytes"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	secret := []byte("12345678123456781234567812345678")
	var sbuf [32]byte

	copy(sbuf[:], secret)

	sb := SecretBoxIO{
		SecretKey: sbuf,
	}

	msg := []byte("This is a very important message that shall be encrypted...")
	r, _, err := sb.ByteReader(msg)
	if err != nil {
		t.Fatalf("encrypting failed: %v", err)
	}

	buf, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("reading ciphertext failed: %v", err)
	}

	w := bytes.NewReader(buf)
	wb := sb.WrapReader(w)

	buf, err = io.ReadAll(wb)
	if err != nil {
		t.Errorf("decrypting failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("did not decrypt, got: %s", buf)
	}
}

func TestIOWrap(t *testing.T) {
	empty := bytes.NewReader(nil)

	sb := SecretBoxIO{}
	wr := sb.WrapReader(empty)

	// An empty stream has no nonce, so it is not ciphertext: the wrapper must refuse it with a clear
	// error rather than pretend it decrypted to nothing.
	buf, err := io.ReadAll(wr)
	if err == nil {
		t.Errorf("expected a short-stream error for empty input, got none")
	}
	if len(buf) != 0 {
		t.Errorf("Buffer should be empty, got: %v", buf)
	}
}
