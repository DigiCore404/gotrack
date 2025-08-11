package main

import (
	"bytes"
	"compress/gzip"
	"net/http"

	"github.com/jackpal/bencode-go"
)

func WriteBencode(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := bencode.Marshal(&buf, v); err != nil {
		http.Error(w, "Bencode error", http.StatusInternalServerError)
		return
	}

	// gzip if enabled
	if config != nil && config.Gzip {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(buf.Bytes())
		_ = gz.Close()
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(buf.Bytes())
}

func BencodeError(w http.ResponseWriter, msg string) {
	WriteBencode(w, map[string]string{"failure reason": msg})
}
