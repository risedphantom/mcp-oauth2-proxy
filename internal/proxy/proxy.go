package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
	"github.com/risedphantom/mcp-oauth2-proxy/internal/middleware"
	"github.com/risedphantom/mcp-oauth2-proxy/utils/httplog"
	log "github.com/sirupsen/logrus"
)

// NewProxy creates an httputil.ReverseProxy configured for streaming (SSE).
// Header mutations from hCfg are applied inside the Rewrite function.
func NewProxy(upCfg config.UpstreamConfig, hCfg config.HeadersConfig) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(upCfg.URL)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		FlushInterval:  -1, // FlushInterval -1 flushes immediately after each write, required for SSE.
		Rewrite:        rewriteRequest(target, hCfg),
		ModifyResponse: logResponse,
		ErrorHandler:   errorHandler,
	}

	log.WithField("upstream", upCfg.URL).Info("Reverse proxy configured")
	return proxy, nil
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.WithError(err).WithField("path", r.URL.Path).Error("Proxy error")
	w.WriteHeader(http.StatusBadGateway)
}

func rewriteRequest(target *url.URL, hCfg config.HeadersConfig) func(*httputil.ProxyRequest) {
	return func(r *httputil.ProxyRequest) {
		r.SetURL(target)

		for _, m := range hCfg.Mutations {
			switch m.Action {
			case config.MutationActionRemove:
				r.Out.Header.Del(m.Name)
			case config.MutationActionSetXForwarded:
				r.SetXForwarded()
			case config.MutationActionAdd:
				if m.ValueFrom != nil {
					var val string
					switch {
					case m.ValueFrom.RequestHeader != "":
						val = r.In.Header.Get(m.ValueFrom.RequestHeader)
					case m.ValueFrom.QueryParameter != "":
						val = r.In.URL.Query().Get(m.ValueFrom.QueryParameter)
					case m.ValueFrom.AuthorizationHeader:
						val = middleware.ExtractBearerToken(r.In)
					}
					r.Out.Header.Set(m.Name, val)
				} else {
					r.Out.Header.Set(m.Name, m.Value)
				}
			}
		}
	}
}

func logResponse(resp *http.Response) error {
	fields := log.Fields{
		"upstream_status":  resp.StatusCode,
		"upstream_url":     resp.Request.URL.Path,
		"upstream_headers": httplog.HeaderMap(resp.Header),
	}

	snippet, body := httplog.CaptureBody(resp.Body, resp.Header.Get("Content-Type"))
	resp.Body = body
	if snippet != nil {
		fields["upstream_body"] = snippet.Content
		if snippet.Truncated {
			fields["upstream_body_truncated"] = true
		}
	}

	log.WithFields(fields).Debug("Upstream response")
	return nil
}
