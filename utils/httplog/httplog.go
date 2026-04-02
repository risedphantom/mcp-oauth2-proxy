package httplog

import (
	"bytes"
	"io"
	"mime"
	"net/http"
)

// MaxBodyLogSize is the maximum number of bytes captured from a request or
// response body for structured logging.
const MaxBodyLogSize = 64 * 1024 // 64 KB

// IsJSONContent returns true if the Content-Type is application/json
// (with any parameters such as charset).
func IsJSONContent(ct string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// HeaderMap converts http.Header to a flat map for structured logging.
func HeaderMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) == 1 {
			m[k] = v[0]
		} else {
			m[k] = h.Get(k)
		}
	}
	return m
}

// ReadBodyPrefix reads up to limit+1 bytes from r to detect truncation.
// It returns all bytes read (up to limit+1) and whether the body exceeded limit.
// The caller should put the full buffer back into the body and log only [:limit].
func ReadBodyPrefix(r io.Reader, limit int) ([]byte, bool) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if err != nil {
		return nil, false
	}
	return buf, len(buf) > limit
}

// BodySnippet holds body text captured for logging.
type BodySnippet struct {
	Content   string
	Truncated bool
}

// CaptureBody reads up to MaxBodyLogSize bytes from body for logging.
// If contentType is not application/json or body is nil/empty, returns (nil, original body).
// Otherwise returns the snippet and a reassembled ReadCloser with all original bytes intact.
func CaptureBody(body io.ReadCloser, contentType string) (*BodySnippet, io.ReadCloser) {
	if body == nil || body == http.NoBody || !IsJSONContent(contentType) {
		return nil, body
	}

	buf, truncated := ReadBodyPrefix(body, MaxBodyLogSize)
	if len(buf) == 0 {
		return nil, body
	}

	logBuf := buf
	if truncated {
		logBuf = buf[:MaxBodyLogSize]
	}

	snippet := &BodySnippet{
		Content:   string(logBuf),
		Truncated: truncated,
	}

	// Reassemble body: bytes we read + remainder still in original body.
	reassembled := io.NopCloser(io.MultiReader(bytes.NewReader(buf), body))
	return snippet, reassembled
}
