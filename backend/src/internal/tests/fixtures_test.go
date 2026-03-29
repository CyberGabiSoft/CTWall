package tests

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"testing"
)

func TestGzipData(t *testing.T) {
	payload := []byte("hello")
	gz := GzipData(t, payload)
	if len(gz) == 0 {
		t.Fatalf("expected gzip bytes")
	}
	if !bytes.HasPrefix(gz, []byte{0x1f, 0x8b}) {
		t.Fatalf("expected gzip header")
	}

	reader, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Fatalf("unexpected payload: %s", decoded)
	}
}

type errGzipWriter struct {
	failWrite bool
	failClose bool
}

func (e *errGzipWriter) Write(_ []byte) (int, error) {
	if e.failWrite {
		return 0, errors.New("write error")
	}
	return 1, nil
}

func (e *errGzipWriter) Close() error {
	if e.failClose {
		return errors.New("close error")
	}
	return nil
}

func TestWriteGzipErrors(t *testing.T) {
	if err := writeGzip(&errGzipWriter{failWrite: true}, []byte("data")); err == nil {
		t.Fatalf("expected write error")
	}
	if err := writeGzip(&errGzipWriter{failClose: true}, []byte("data")); err == nil {
		t.Fatalf("expected close error")
	}
}
