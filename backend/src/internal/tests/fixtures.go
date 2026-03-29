package tests

import (
	"bytes"
	"compress/gzip"
	"testing"
)

var (
	SBOMInvalidJSON = []byte(`{"components":}`)
)

// GzipData returns gzip-compressed data for tests.
func GzipData(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_ = writeGzip(writer, data)
	return buf.Bytes()
}

type gzipWriter interface {
	Write([]byte) (int, error)
	Close() error
}

func writeGzip(writer gzipWriter, data []byte) error {
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return nil
}
