package httplog

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIsJSONContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"APPLICATION/JSON", true},
		{"text/plain", false},
		{"text/event-stream", false},
		{"", false},
		{";;;invalid", false},
		{"application/json-patch+json", false},
	}
	for _, tt := range tests {
		if got := IsJSONContent(tt.ct); got != tt.want {
			t.Errorf("IsJSONContent(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

func TestHeaderMap(t *testing.T) {
	t.Parallel()

	t.Run("single value headers", func(t *testing.T) {
		t.Parallel()
		h := http.Header{"X-One": {"val1"}, "X-Two": {"val2"}}
		m := HeaderMap(h)
		if m["X-One"] != "val1" {
			t.Errorf("expected X-One=val1, got %s", m["X-One"])
		}
		if m["X-Two"] != "val2" {
			t.Errorf("expected X-Two=val2, got %s", m["X-Two"])
		}
	})

	t.Run("multi value headers", func(t *testing.T) {
		t.Parallel()
		h := http.Header{"X-Multi": {"a", "b"}}
		m := HeaderMap(h)
		// http.Header.Get returns the first value joined by ", " for canonical form.
		if m["X-Multi"] == "" {
			t.Error("expected X-Multi to have a value")
		}
	})

	t.Run("empty headers", func(t *testing.T) {
		t.Parallel()
		m := HeaderMap(http.Header{})
		if len(m) != 0 {
			t.Errorf("expected empty map, got %v", m)
		}
	})
}

func TestReadBodyPrefix(t *testing.T) {
	t.Parallel()

	t.Run("under limit", func(t *testing.T) {
		t.Parallel()
		buf, truncated := ReadBodyPrefix(strings.NewReader("hello"), 10)
		if string(buf) != "hello" || truncated {
			t.Errorf("got %q truncated=%v, want %q truncated=false", buf, truncated, "hello")
		}
	})

	t.Run("exactly at limit", func(t *testing.T) {
		t.Parallel()
		buf, truncated := ReadBodyPrefix(strings.NewReader("12345"), 5)
		if string(buf) != "12345" || truncated {
			t.Errorf("got %q truncated=%v, want %q truncated=false", buf, truncated, "12345")
		}
	})

	t.Run("over limit", func(t *testing.T) {
		t.Parallel()
		buf, truncated := ReadBodyPrefix(strings.NewReader("123456"), 5)
		if string(buf) != "123456" || !truncated {
			t.Errorf("got %q truncated=%v, want %q truncated=true", buf, truncated, "123456")
		}
	})

	t.Run("empty reader", func(t *testing.T) {
		t.Parallel()
		buf, truncated := ReadBodyPrefix(strings.NewReader(""), 10)
		if len(buf) != 0 || truncated {
			t.Errorf("got %q truncated=%v, want empty truncated=false", buf, truncated)
		}
	})
}

func TestCaptureBody_JSON(t *testing.T) {
	t.Parallel()

	body := `{"jsonrpc":"2.0","id":1}`
	rc := io.NopCloser(strings.NewReader(body))

	snippet, reassembled := CaptureBody(rc, "application/json")
	if snippet == nil {
		t.Fatal("expected non-nil snippet for JSON body")
		return
	}
	if snippet.Content != body {
		t.Errorf("expected content %q, got %q", body, snippet.Content)
	}
	if snippet.Truncated {
		t.Error("did not expect truncation for small body")
	}

	// Reassembled body must contain the full original content.
	all, err := io.ReadAll(reassembled)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(all) != body {
		t.Errorf("reassembled body %q, want %q", all, body)
	}
}

func TestCaptureBody_Truncation(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("x", MaxBodyLogSize+100)
	rc := io.NopCloser(strings.NewReader(large))

	snippet, reassembled := CaptureBody(rc, "application/json; charset=utf-8")
	if snippet == nil {
		t.Fatal("expected non-nil snippet")
		return
	}
	if !snippet.Truncated {
		t.Error("expected truncation for large body")
	}
	if len(snippet.Content) != MaxBodyLogSize {
		t.Errorf("expected content len=%d, got %d", MaxBodyLogSize, len(snippet.Content))
	}

	// Reassembled body must still contain the full content.
	all, err := io.ReadAll(reassembled)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if len(all) != len(large) {
		t.Errorf("reassembled body len=%d, want %d", len(all), len(large))
	}
}

func TestCaptureBody_NonJSON(t *testing.T) {
	t.Parallel()

	rc := io.NopCloser(strings.NewReader("data: hello\n\n"))
	snippet, body := CaptureBody(rc, "text/event-stream")
	if snippet != nil {
		t.Error("expected nil snippet for non-JSON content type")
	}
	if body != rc {
		t.Error("expected original body to be returned unchanged")
	}
}

func TestCaptureBody_NilBody(t *testing.T) {
	t.Parallel()

	snippet, body := CaptureBody(nil, "application/json")
	if snippet != nil {
		t.Error("expected nil snippet for nil body")
	}
	if body != nil {
		t.Error("expected nil body returned")
	}
}

func TestCaptureBody_NoBody(t *testing.T) {
	t.Parallel()

	snippet, body := CaptureBody(http.NoBody, "application/json")
	if snippet != nil {
		t.Error("expected nil snippet for http.NoBody")
	}
	if body != http.NoBody {
		t.Error("expected http.NoBody returned unchanged")
	}
}
