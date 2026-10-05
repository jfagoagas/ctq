package ct

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const userAgent = "ctq/0.1"

// HTTPError is a non-2xx response.
type HTTPError struct {
	URL  string
	Code int
	Body string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d from %s: %s", e.Code, e.URL, e.Body)
}

// Client is a GET-only HTTP client with retries. Every backend here is flaky in
// its own way (crt.sh DB timeouts, Cert Spotter 429s, CT logs throttling).
type Client struct {
	HTTP          *http.Client
	Retries       int
	Backoff       time.Duration
	MaxRetryAfter time.Duration
}

func NewClient(timeout time.Duration, retries int) *Client {
	return &Client{
		HTTP:          &http.Client{Timeout: timeout},
		Retries:       retries,
		Backoff:       2 * time.Second,
		MaxRetryAfter: time.Minute,
	}
}

type Response struct {
	Header http.Header
	Body   []byte
}

func retryable(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

func (c *Client) Get(ctx context.Context, rawURL string, header map[string]string) (*Response, error) {
	var last error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		delay := c.Backoff << attempt

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range header {
			req.Header.Set(k, v)
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = err
		} else {
			// 64 MiB cap: a full data tile is ~1-2 MiB, crt.sh results for huge domains are bigger.
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			resp.Body.Close()
			switch {
			case rerr != nil:
				last = rerr
			case resp.StatusCode < 300:
				return &Response{Header: resp.Header, Body: body}, nil
			default:
				herr := &HTTPError{URL: redact(rawURL), Code: resp.StatusCode, Body: snippet(body)}
				if !retryable(resp.StatusCode) {
					return nil, herr
				}
				last = herr
				if wait, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
					if wait > c.MaxRetryAfter {
						// Cert Spotter asks for up to an hour. Fail now instead of hanging the CLI.
						return nil, fmt.Errorf("rate limited, server asks to wait %s: %w", wait, herr)
					}
					delay = wait
				}
			}
		}

		if attempt == c.Retries {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", c.Retries+1, last)
}

// IsNotFound reports whether err is an HTTP 404.
func IsNotFound(err error) bool {
	var h *HTTPError
	return errors.As(err, &h) && h.Code == http.StatusNotFound
}

func retryAfter(v string) (time.Duration, bool) {
	// The HTTP-date form is legal too, but none of these backends send it.
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

func snippet(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return strconv.Quote(string(b))
}

// redact drops the query string so errors never echo tokens or long parameter lists.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}
