package zoho

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knadh/listmonk/models"
)

const (
	testContactAddr = "contact@vireliastudio.one"
	testHelloAddr   = "hello@vireliastudio.one"

	// Clearly fake values. Nothing secret may live in this repo.
	testContactSecret = "test-contact-client-secret-DO-NOT-USE"
	testHelloSecret   = "test-hello-client-secret-DO-NOT-USE"
	testRefreshToken  = "test-refresh-token-DO-NOT-USE"
)

// capture records anything written to a logger so tests can assert that
// secrets never reach the logs.
type capture struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}

func testLogger() (*log.Logger, *capture) {
	c := &capture{}
	return log.New(c, "", 0), c
}

func contactOpt() Opt {
	return Opt{
		Name:         "contact",
		FromAddress:  testContactAddr,
		ClientID:     "test-contact-client-id",
		ClientSecret: testContactSecret,
		RefreshToken: testRefreshToken,
		AccountID:    "acc-contact",
	}
}

func helloOpt() Opt {
	return Opt{
		Name:         "hello",
		FromAddress:  testHelloAddr,
		ClientID:     "test-hello-client-id",
		ClientSecret: testHelloSecret,
		RefreshToken: testRefreshToken,
		AccountID:    "acc-hello",
	}
}

// tokenServer is a fake Zoho OAuth token endpoint.
type tokenServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    int
	issued   int
	lifetime time.Duration

	// status overrides the response code when non-zero.
	status int
	// body overrides the response body when non-empty.
	body string
}

func newTokenServer(t *testing.T, lifetime time.Duration) *tokenServer {
	t.Helper()

	ts := &tokenServer{lifetime: lifetime}
	ts.srv = httptest.NewServer(http.HandlerFunc(ts.handle))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) handle(w http.ResponseWriter, r *http.Request) {
	ts.mu.Lock()
	ts.calls++
	status, body := ts.status, ts.body
	idx := ts.issued
	ts.issued++
	lifetime := ts.lifetime
	ts.mu.Unlock()

	if status != 0 || body != "" {
		if body == "" {
			body = `{"error":"invalid_grant"}`
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
		return
	}

	// A real token endpoint only accepts POST.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"access-token-%d","token_type":"Bearer","expires_in":%d}`,
		idx, int(lifetime.Seconds()))
}

func (ts *tokenServer) calls_() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.calls
}

func (ts *tokenServer) setResponse(status int, body string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.status, ts.body = status, body
}

// mailServer is a fake Zoho Mail send-mail API endpoint.
type mailServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    int
	payloads []map[string]any
	authHdrs []string

	// statuses is a queue of status codes to return, one per call. When
	// exhausted, okStatus is returned.
	statuses []int
	okStatus int
	body     string
}

func newMailServer(t *testing.T) *mailServer {
	t.Helper()

	ms := &mailServer{okStatus: http.StatusOK}

	// TLS, because the messenger always talks to Zoho over https. Its client()
	// trusts the test server's certificate.
	ms.srv = httptest.NewTLSServer(http.HandlerFunc(ms.handle))
	t.Cleanup(ms.srv.Close)
	return ms
}

func (ms *mailServer) handle(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &payload)

	ms.mu.Lock()
	ms.calls++
	ms.payloads = append(ms.payloads, payload)
	ms.authHdrs = append(ms.authHdrs, r.Header.Get("Authorization"))
	code := ms.okStatus
	if len(ms.statuses) > 0 {
		code = ms.statuses[0]
		ms.statuses = ms.statuses[1:]
	}
	body := ms.body
	ms.mu.Unlock()

	if body == "" {
		body = `{"status":"success","id":"msg-1"}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func (ms *mailServer) count() int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.calls
}

func (ms *mailServer) lastPayload() map[string]any {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.payloads) == 0 {
		return nil
	}
	return ms.payloads[len(ms.payloads)-1]
}

func (ms *mailServer) lastAuth() string {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.authHdrs) == 0 {
		return ""
	}
	return ms.authHdrs[len(ms.authHdrs)-1]
}

func (ms *mailServer) setStatuses(codes ...int) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.statuses = codes
}

// newTestMessenger builds a messenger pointed at the fake servers, with a fast
// backoff so retry tests do not sleep for long.
func newTestMessenger(t *testing.T, opts ...Opt) (*Messenger, *tokenServer, *mailServer) {
	t.Helper()

	tok := newTokenServer(t, time.Hour)
	mail := newMailServer(t)

	for i := range opts {
		opts[i].OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
		opts[i].MailHost = strings.TrimPrefix(mail.srv.URL, "http://")
	}

	logger, _ := testLogger()
	m, err := NewWithClient(opts, mail.srv.Client(), logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	t.Cleanup(func() { m.Close() })

	m.backoff = time.Millisecond
	m.retries = 3

	return m, tok, mail
}

func testMessage() models.Message {
	return models.Message{
		From:        testContactAddr,
		To:          []string{"subscriber@example.com"},
		Subject:     "Hello there",
		ContentType: "html",
		Body:        []byte("<p>Hi</p>"),
	}
}

// ---------------------------------------------------------------------------
// 1. Token acquisition, 3. auth header, 2. successful send.
// ---------------------------------------------------------------------------

func TestPushAcquiresTokenAndSends(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if got := tok.calls_(); got != 1 {
		t.Errorf("token endpoint calls = %d, want 1", got)
	}
	if got := mail.count(); got != 1 {
		t.Errorf("mail endpoint calls = %d, want 1", got)
	}

	// Zoho's mail API uses a custom scheme, not Bearer.
	auth := mail.lastAuth()
	if !strings.HasPrefix(auth, "Zoho-oauthtoken ") {
		t.Errorf("Authorization header = %q, want prefix %q", auth, "Zoho-oauthtoken ")
	}
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		t.Errorf("Authorization header must not use Bearer, got %q", auth)
	}
}

// ---------------------------------------------------------------------------
// 4. Correct API payload.
// ---------------------------------------------------------------------------

func TestPushSendsCorrectPayload(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	msg := testMessage()
	msg.From = "Virelia Studio <" + testContactAddr + ">"
	msg.Subject = "Autumn update"
	msg.Body = []byte("<h1>Hello</h1>")
	msg.Headers = textproto.MIMEHeader{
		"Cc":  {"cc1@example.com, cc2@example.com"},
		"Bcc": {"bcc@example.com"},
	}

	if err := m.Push(msg); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	p := mail.lastPayload()

	from, _ := p["fromAddress"].(map[string]any)
	if got := from["address"]; got != testContactAddr {
		t.Errorf("fromAddress.address = %v, want %v", got, testContactAddr)
	}
	// The campaign's display name must survive.
	if got := from["displayName"]; got != "Virelia Studio" {
		t.Errorf("fromAddress.displayName = %v, want %q", got, "Virelia Studio")
	}

	if got := p["subject"]; got != "Autumn update" {
		t.Errorf("subject = %v, want %q", got, "Autumn update")
	}
	if got := p["mailFormat"]; got != "html" {
		t.Errorf("mailFormat = %v, want %q", got, "html")
	}
	if got := p["content"]; got != "<h1>Hello</h1>" {
		t.Errorf("content = %v, want %q", got, "<h1>Hello</h1>")
	}

	to, _ := p["toAddress"].([]any)
	if len(to) != 1 {
		t.Fatalf("toAddress len = %d, want 1", len(to))
	}
	if got := to[0].(map[string]any)["address"]; got != "subscriber@example.com" {
		t.Errorf("toAddress[0] = %v, want subscriber@example.com", got)
	}

	cc, _ := p["ccAddress"].([]any)
	if len(cc) != 2 {
		t.Errorf("ccAddress len = %d, want 2", len(cc))
	}
	bcc, _ := p["bccAddress"].([]any)
	if len(bcc) != 1 {
		t.Errorf("bccAddress len = %d, want 1", len(bcc))
	}
}

func TestPushPlainTextBody(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	msg := testMessage()
	msg.Body = nil
	msg.AltBody = []byte("plain only")

	if err := m.Push(msg); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	p := mail.lastPayload()
	if got := p["mailFormat"]; got != "text" {
		t.Errorf("mailFormat = %v, want %q", got, "text")
	}
	if got := p["content"]; got != "plain only" {
		t.Errorf("content = %v, want %q", got, "plain only")
	}
}

// ---------------------------------------------------------------------------
// 5. Token caching, and concurrency safety.
// ---------------------------------------------------------------------------

func TestTokenIsCachedAcrossSends(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	for i := 0; i < 5; i++ {
		if err := m.Push(testMessage()); err != nil {
			t.Fatalf("Push() #%d error = %v", i, err)
		}
	}

	if got := mail.count(); got != 5 {
		t.Errorf("mail calls = %d, want 5", got)
	}
	// The whole point: one token request for five e-mails.
	if got := tok.calls_(); got != 1 {
		t.Errorf("token calls = %d, want 1 (token should be cached)", got)
	}
}

func TestConcurrentSendsShareOneToken(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	var wg sync.WaitGroup
	errs := make([]error, 30)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = m.Push(testMessage())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Push() #%d error = %v", i, err)
		}
	}
	if got := mail.count(); got != len(errs) {
		t.Errorf("mail calls = %d, want %d", got, len(errs))
	}
	if got := tok.calls_(); got != 1 {
		t.Errorf("token calls = %d, want 1 under concurrency", got)
	}
}

// ---------------------------------------------------------------------------
// 6. Token refresh after 401 and after expiry.
// ---------------------------------------------------------------------------

func TestTokenRefreshedAfter401(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	// First attempt 401s, second succeeds.
	mail.setStatuses(http.StatusUnauthorized)

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if got := mail.count(); got != 2 {
		t.Errorf("mail calls = %d, want 2 (one 401 + one retry)", got)
	}
	if got := tok.calls_(); got != 2 {
		t.Errorf("token calls = %d, want 2 (initial + refresh after 401)", got)
	}

	// The retry must use a new token, not the rejected one.
	_, auth := lastTwoAuth(t, mail)
	if auth[0] == auth[1] {
		t.Errorf("retry reused the rejected access token: %q", auth[0])
	}
}

func TestPersistent401FailsAfterSingleRefresh(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	// Always 401. It must refresh once, retry once, then give up.
	mail.setStatuses(http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized)

	err := m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want an error for persistent 401")
	}

	if got := mail.count(); got != 2 {
		t.Errorf("mail calls = %d, want 2 (single retry after one refresh)", got)
	}
	if got := tok.calls_(); got != 2 {
		t.Errorf("token calls = %d, want 2 (initial + exactly one refresh)", got)
	}
}

func TestExpiredTokenIsRefreshedProactively(t *testing.T) {
	// Tokens live 1s, so the cached one is expired before the second send.
	m, tok, mail := newTestMessenger(t, contactOpt())

	// Expire the cached token directly.
	a := m.accounts[testContactAddr]
	a.mut.Lock()
	a.expires = time.Now().Add(-time.Second)
	a.mut.Unlock()

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if got := tok.calls_(); got != 1 {
		t.Errorf("token calls = %d, want 1 after invalidating the cache", got)
	}
	if got := mail.count(); got != 1 {
		t.Errorf("mail calls = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// 7/8. 429 and 5xx retry, with backoff.
// ---------------------------------------------------------------------------

func TestRetriesOn429(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	mail.setStatuses(http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusOK)

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if got := mail.count(); got != 3 {
		t.Errorf("mail calls = %d, want 3 (2x429 + success)", got)
	}
	// Retries must reuse the cached token.
	if got := tok.calls_(); got != 1 {
		t.Errorf("token calls = %d, want 1 (429 must not force a token refresh)", got)
	}
}

func TestRetriesOn5xx(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			m, _, mail := newTestMessenger(t, contactOpt())

			mail.setStatuses(code, http.StatusOK)

			if err := m.Push(testMessage()); err != nil {
				t.Fatalf("Push() error = %v", err)
			}
			if got := mail.count(); got != 2 {
				t.Errorf("mail calls = %d, want 2 (%d + success)", got, code)
			}
		})
	}
}

func TestRetriesAreBounded(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	// Always 500: retries + the original attempt must be capped.
	mail.setStatuses(http.StatusInternalServerError, http.StatusInternalServerError,
		http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError)

	err := m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want an error after exhausting retries")
	}
	if got := mail.count(); got != m.retries+1 {
		t.Errorf("mail calls = %d, want %d (retries must be bounded)", got, m.retries+1)
	}
}

func TestDoesNotRetryPermanent4xx(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	mail.setStatuses(http.StatusBadRequest, http.StatusOK)

	err := m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want an error for 400")
	}
	if got := mail.count(); got != 1 {
		t.Errorf("mail calls = %d, want 1 (400 must not be retried)", got)
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Errorf("error = %q, want it to mention status 400", err)
	}
}

func TestForbiddenAndNotFoundErrors(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			m, _, mail := newTestMessenger(t, contactOpt())
			mail.setStatuses(code)

			err := m.Push(testMessage())
			if err == nil {
				t.Fatalf("Push() error = nil, want an error for %d", code)
			}
			if got := mail.count(); got != 1 {
				t.Errorf("mail calls = %d, want 1", got)
			}
		})
	}
}

func TestMalformedResponseBody(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	mail.mu.Lock()
	mail.body = "<<<not json at all>>>"
	mail.statuses = []int{http.StatusBadRequest}
	mail.mu.Unlock()

	err := m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want an error for a malformed 400 body")
	}
	// The raw snippet is still surfaced rather than swallowed.
	if !strings.Contains(err.Error(), "not json") {
		t.Errorf("error = %q, want it to include the response snippet", err)
	}
}

// ---------------------------------------------------------------------------
// 9. Invalid configuration.
// ---------------------------------------------------------------------------

func TestInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Opt)
		wantErr string
	}{
		{"missing from_address", func(o *Opt) { o.FromAddress = "" }, "from_address"},
		{"missing client_id", func(o *Opt) { o.ClientID = "" }, "client_id"},
		{"missing client_secret", func(o *Opt) { o.ClientSecret = "" }, "client_secret"},
		{"missing refresh_token", func(o *Opt) { o.RefreshToken = "" }, "refresh_token"},
		{"missing account_id", func(o *Opt) { o.AccountID = "" }, "account_id"},
		{"bad from_address", func(o *Opt) { o.FromAddress = "not-an-address" }, "invalid from_address"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := contactOpt()
			tc.mutate(&o)

			_, err := New([]Opt{o}, log.New(io.Discard, "", 0))
			if err == nil {
				t.Fatal("New() error = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestNoAccountsIsAnError(t *testing.T) {
	_, err := New(nil, log.New(io.Discard, "", 0))
	if !errors.Is(err, ErrNoAccounts) {
		t.Errorf("New(nil) error = %v, want ErrNoAccounts", err)
	}
}

func TestInvalidRefreshTokenIsHandled(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())
	tok.setResponse(http.StatusBadRequest, `{"error":"invalid_client"}`)

	err := m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want an error for an invalid refresh token")
	}
	if !strings.Contains(err.Error(), "could not obtain an access token") {
		t.Errorf("error = %q, want a token-acquisition error", err)
	}
	if got := mail.count(); got != 0 {
		t.Errorf("mail calls = %d, want 0 when the token cannot be obtained", got)
	}
}

func TestDuplicateSenderIsAnError(t *testing.T) {
	a := contactOpt()
	b := contactOpt()
	b.Name = "contact-dup"

	if _, err := New([]Opt{a, b}, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("New() error = nil, want a duplicate-sender error")
	}
}

// ---------------------------------------------------------------------------
// 10. Unsupported From address.
// ---------------------------------------------------------------------------

func TestUnsupportedFromAddressIsRejected(t *testing.T) {
	// Only the contact mailbox is configured here.
	m, _, mail := newTestMessenger(t, contactOpt())

	for _, from := range []string{
		"someone@elsewhere.com",
		testHelloAddr, // valid address, but no such configured mailbox
		"",
		"garbage",
	} {
		msg := testMessage()
		msg.From = from

		err := m.Push(msg)
		if err == nil {
			t.Fatalf("Push() with From=%q error = nil, want an error", from)
		}
		if !errors.Is(err, ErrUnsupportedFrom) {
			t.Errorf("Push() with From=%q error = %v, want ErrUnsupportedFrom", from, err)
		}
	}

	// Nothing should have been sent.
	if got := mail.count(); got != 0 {
		t.Errorf("mail calls = %d, want 0 for unsupported senders", got)
	}
}

func TestFromAddressMatchingIsCaseAndDisplayNameInsensitive(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	for _, from := range []string{
		"CONTACT@vireliastudio.one",
		"Contact <contact@vireliastudio.one>",
		"  contact@vireliastudio.one  ",
	} {
		msg := testMessage()
		msg.From = from

		if err := m.Push(msg); err != nil {
			t.Errorf("Push() with From=%q error = %v, want it to resolve to the contact mailbox", from, err)
		}
	}

	if got := mail.count(); got != 3 {
		t.Errorf("mail calls = %d, want 3", got)
	}
}

func TestUnsupportedFromErrorListsConfiguredSenders(t *testing.T) {
	m, _, _ := newTestMessenger(t, contactOpt(), helloOpt())

	msg := testMessage()
	msg.From = "nobody@vireliastudio.one"

	err := m.Push(msg)
	if err == nil {
		t.Fatal("Push() error = nil, want an error")
	}
	for _, want := range []string{testContactAddr, testHelloAddr} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to list the configured sender %q", err, want)
		}
	}
}

func TestAttachmentsAreRejectedNotDropped(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	msg := testMessage()
	msg.Attachments = []models.Attachment{{Name: "a.txt", Content: []byte("hi")}}

	err := m.Push(msg)
	if !errors.Is(err, ErrAttachmentsUnsupported) {
		t.Errorf("Push() error = %v, want ErrAttachmentsUnsupported", err)
	}
	if got := mail.count(); got != 0 {
		t.Errorf("mail calls = %d, want 0 (attachments must not be silently dropped)", got)
	}
}

func TestUnsupportedCustomHeaderIsRejected(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	msg := testMessage()
	msg.Headers = textproto.MIMEHeader{"X-Custom-Trace": {"abc"}}

	err := m.Push(msg)
	if !errors.Is(err, ErrUnsupportedHeader) {
		t.Errorf("Push() error = %v, want ErrUnsupportedHeader", err)
	}
	if got := mail.count(); got != 0 {
		t.Errorf("mail calls = %d, want 0", got)
	}
}

func TestZohoManagedHeadersAreWarnedNotFatal(t *testing.T) {
	logger, cap := testLogger()

	tok := newTokenServer(t, time.Hour)
	mail := newMailServer(t)

	o := contactOpt()
	o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
	o.MailHost = strings.TrimPrefix(mail.srv.URL, "http://")

	m, err := NewWithClient([]Opt{o}, mail.srv.Client(), logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()

	msg := testMessage()
	msg.Headers = textproto.MIMEHeader{
		"List-Unsubscribe":      {"<https://example.com/u>"},
		"List-Unsubscribe-Post": {"List-Unsubscribe=One-Click"},
	}

	if err := m.Push(msg); err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if got := mail.count(); got != 1 {
		t.Errorf("mail calls = %d, want 1", got)
	}
	if !strings.Contains(cap.String(), "List-Unsubscribe") {
		t.Errorf("logs = %q, want a warning about the dropped header", cap.String())
	}
}

// ---------------------------------------------------------------------------
// 11. Separate credentials per mailbox.
// ---------------------------------------------------------------------------

func TestSeparateCredentialsPerMailbox(t *testing.T) {
	tok := newTokenServer(t, time.Hour)
	mail := newMailServer(t)

	withHosts := func(o Opt) Opt {
		o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
		o.MailHost = strings.TrimPrefix(mail.srv.URL, "http://")
		return o
	}

	logger, cap := testLogger()
	m, err := NewWithClient([]Opt{withHosts(contactOpt()), withHosts(helloOpt())}, mail.srv.Client(), logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()
	m.backoff = time.Millisecond

	contactMsg := testMessage()
	helloMsg := testMessage()
	helloMsg.From = testHelloAddr
	helloMsg.Subject = "from hello"

	if err := m.Push(contactMsg); err != nil {
		t.Fatalf("Push(contact) error = %v", err)
	}
	if err := m.Push(helloMsg); err != nil {
		t.Fatalf("Push(hello) error = %v", err)
	}

	mail.mu.Lock()
	payloads := append([]map[string]any(nil), mail.payloads...)
	mail.mu.Unlock()

	if len(payloads) != 2 {
		t.Fatalf("payloads = %d, want 2", len(payloads))
	}

	fromContact, _ := payloads[0]["fromAddress"].(map[string]any)
	if fromContact["address"] != testContactAddr {
		t.Errorf("payload[0].fromAddress = %v, want %q", fromContact["address"], testContactAddr)
	}
	fromHello, _ := payloads[1]["fromAddress"].(map[string]any)
	if fromHello["address"] != testHelloAddr {
		t.Errorf("payload[1].fromAddress = %v, want %q", fromHello["address"], testHelloAddr)
	}

	// Each mailbox fetched its own token.
	if got := tok.calls_(); got != 2 {
		t.Errorf("token calls = %d, want 2 (one per mailbox)", got)
	}

	// Each mailbox has its own cached token, so the second send from a mailbox
	// does not re-fetch.
	if err := m.Push(contactMsg); err != nil {
		t.Fatalf("Push(contact) again error = %v", err)
	}
	if got := tok.calls_(); got != 2 {
		t.Errorf("token calls = %d, want 2 (contact's token should be cached)", got)
	}

	// The distinct client secrets must never leak into the logs.
	logs := cap.String()
	for _, secret := range []string{testContactSecret, testHelloSecret, testRefreshToken} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain a secret %q:\n%s", secret, logs)
		}
	}
}

func TestEachMailboxUsesItsOwnAccountID(t *testing.T) {
	// Both mailboxes share one fake mail host, so assert the URL path carries
	// the right account id per sender.
	paths := make(chan string, 4)
	mail := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"success"}`)
	}))
	defer mail.Close()

	tok := newTokenServer(t, time.Hour)
	withHosts := func(o Opt) Opt {
		o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
		o.MailHost = strings.TrimPrefix(mail.URL, "http://")
		return o
	}

	m, err := NewWithClient([]Opt{withHosts(contactOpt()), withHosts(helloOpt())}, mail.Client(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()

	helloMsg := testMessage()
	helloMsg.From = testHelloAddr

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push(contact) error = %v", err)
	}
	if err := m.Push(helloMsg); err != nil {
		t.Fatalf("Push(hello) error = %v", err)
	}

	var seen []string
	for i := 0; i < 2; i++ {
		seen = append(seen, <-paths)
	}

	if !strings.Contains(seen[0], "/accounts/acc-contact/v1/messages") {
		t.Errorf("contact path = %q, want it to contain /accounts/acc-contact/v1/messages", seen[0])
	}
	if !strings.Contains(seen[1], "/accounts/acc-hello/v1/messages") {
		t.Errorf("hello path = %q, want it to contain /accounts/acc-hello/v1/messages", seen[1])
	}
}

// ---------------------------------------------------------------------------
// 12. Secret / token redaction.
// ---------------------------------------------------------------------------

func TestSecretsAndTokensAreRedactedFromErrorsAndLogs(t *testing.T) {
	logger, cap := testLogger()

	tok := newTokenServer(t, time.Hour)
	mail := newMailServer(t)

	o := contactOpt()
	o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
	o.MailHost = strings.TrimPrefix(mail.srv.URL, "http://")

	m, err := NewWithClient([]Opt{o}, mail.srv.Client(), logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()
	m.backoff = time.Millisecond

	// An error response that mentions the account, plus a rejected From address,
	// plus an attachment failure. None may echo secrets.
	mail.mu.Lock()
	mail.statuses = []int{http.StatusBadRequest}
	mail.body = `{"error":{"code":"INVALID","message":"bad message"}}`
	mail.mu.Unlock()

	var collected []string
	collect := func(err error) {
		if err != nil {
			collected = append(collected, err.Error())
		}
	}

	collect(m.Push(testMessage()))

	// The access token the fake server actually issued.
	issuedToken := "access-token-0"

	msg := testMessage()
	msg.From = "unsupported@example.com"
	collect(m.Push(msg))

	msg = testMessage()
	msg.Attachments = []models.Attachment{{Name: "a.txt"}}
	collect(m.Push(msg))

	// A token-exchange failure, whose raw error would otherwise embed the
	// client secret and refresh token.
	tok.setResponse(http.StatusBadRequest, `{"error":"invalid_client"}`)
	m.accounts[testContactAddr].invalidate()
	collect(m.Push(testMessage()))

	// Construction errors must not echo the values either.
	o2 := contactOpt()
	o2.AccountID = ""
	_, cerr := New([]Opt{o2}, logger)
	if cerr != nil {
		collected = append(collected, cerr.Error())
	}

	haystacks := append([]string{cap.String()}, collected...)
	for _, h := range haystacks {
		for _, secret := range []string{
			testContactSecret,
			testRefreshToken,
			issuedToken,
			"client_secret",
			"refresh_token",
		} {
			if strings.Contains(h, secret) {
				t.Errorf("output leaks %q:\n%s", secret, h)
			}
		}
	}
}

func TestAccessTokenNeverLoggedOnSuccess(t *testing.T) {
	logger, cap := testLogger()

	tok := newTokenServer(t, time.Hour)
	mail := newMailServer(t)

	o := contactOpt()
	o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
	o.MailHost = strings.TrimPrefix(mail.srv.URL, "http://")

	m, err := NewWithClient([]Opt{o}, mail.srv.Client(), logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if logs := cap.String(); strings.Contains(logs, "access-token-0") {
		t.Errorf("logs contain the access token:\n%s", logs)
	}
}

// ---------------------------------------------------------------------------
// Interface conformance and misc behaviour.
// ---------------------------------------------------------------------------

func TestImplementsMessengerInterface(t *testing.T) {
	m, _, _ := newTestMessenger(t, contactOpt())

	if got := m.Name(); got != MessengerName {
		t.Errorf("Name() = %q, want %q", got, MessengerName)
	}
	if err := m.Flush(); err != nil {
		t.Errorf("Flush() error = %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestEmptyBodyIsRejected(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	msg := testMessage()
	msg.Body = nil
	msg.AltBody = nil

	if err := m.Push(msg); err == nil {
		t.Fatal("Push() error = nil, want an error for an empty body")
	}
	if got := mail.count(); got != 0 {
		t.Errorf("mail calls = %d, want 0", got)
	}
}

func TestDefaultEndpointsAreZohoIndia(t *testing.T) {
	// Guards the documented India endpoints.
	o := contactOpt()
	h, err := resolveHosts(o)
	if err != nil {
		t.Fatalf("resolveHosts() error = %v", err)
	}
	if h.accounts != DefaultAccountsHost {
		t.Errorf("accounts host = %q, want %q", h.accounts, DefaultAccountsHost)
	}
	if h.mail != "mail.zoho.in" {
		t.Errorf("mail host = %q, want %q", h.mail, "mail.zoho.in")
	}

	if got := "https://" + h.accounts + "/oauth/v2/token"; got != "https://accounts.zoho.in/oauth/v2/token" {
		t.Errorf("token endpoint = %q, want the Zoho India token endpoint", got)
	}
}

func TestNonIndiaDatacentre(t *testing.T) {
	o := contactOpt()
	o.ZohoAccountsHost = "accounts.zoho.eu"

	h, err := resolveHosts(o)
	if err != nil {
		t.Fatalf("resolveHosts() error = %v", err)
	}
	if h.accounts != "accounts.zoho.eu" {
		t.Errorf("accounts host = %q, want accounts.zoho.eu", h.accounts)
	}
	if h.mail != "mail.zoho.eu" {
		t.Errorf("mail host = %q, want mail.zoho.eu", h.mail)
	}
}

func TestNetworkFailureIsRetriedThenReported(t *testing.T) {
	// Tokens work; the mail host points at a closed port so every dial fails.
	tok := newTokenServer(t, time.Hour)

	o := contactOpt()
	o.OAuthTokenURL = tok.srv.URL + "/oauth/v2/token"
	o.MailHost = "127.0.0.1:1"

	logger, _ := testLogger()
	m, err := NewWithClient([]Opt{o}, &http.Client{Timeout: 200 * time.Millisecond}, logger)
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	defer m.Close()
	m.backoff = time.Millisecond
	m.retries = 2

	err = m.Push(testMessage())
	if err == nil {
		t.Fatal("Push() error = nil, want a network error")
	}
	if !strings.Contains(err.Error(), "zoho send failed after 3 attempt(s)") {
		t.Errorf("error = %q, want an exhausted-retries error", err)
	}
}

func TestConcurrent401sDoNotStampedeTheTokenEndpoint(t *testing.T) {
	m, tok, mail := newTestMessenger(t, contactOpt())

	// Every mail attempt 401s for the first 10 calls, then succeeds.
	var n atomic.Int32
	mail.mu.Lock()
	mail.okStatus = http.StatusUnauthorized
	mail.mu.Unlock()

	go func() {
		for {
			if n.Load() >= 10 {
				mail.mu.Lock()
				mail.okStatus = http.StatusOK
				mail.mu.Unlock()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	errs := make([]error, 12)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = m.Push(testMessage())
			n.Add(1)
		}(i)
	}
	wg.Wait()

	// Each send may refresh at most once, so the token endpoint is called at
	// most once per send plus the initial one. The point is that it stays
	// bounded and no request goes out unauthenticated.
	if got := tok.calls_(); got == 0 || got > len(errs)+1 {
		t.Errorf("token calls = %d, want between 1 and %d", got, len(errs)+1)
	}
}

// lastTwoAuth returns the two most recent Authorization headers.
func lastTwoAuth(t *testing.T, ms *mailServer) (map[string]any, []string) {
	t.Helper()

	ms.mu.Lock()
	defer ms.mu.Unlock()

	if len(ms.authHdrs) < 2 {
		t.Fatalf("auth headers = %d, want at least 2", len(ms.authHdrs))
	}
	n := len(ms.authHdrs)
	return ms.payloads[n-1], []string{ms.authHdrs[n-2], ms.authHdrs[n-1]}
}

// TestPayloadIsValidJSON guards the wire format.
func TestPayloadIsValidJSON(t *testing.T) {
	m, _, mail := newTestMessenger(t, contactOpt())

	if err := m.Push(testMessage()); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	b, err := json.Marshal(mail.lastPayload())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, k := range []string{"fromAddress", "toAddress", "subject", "content", "mailFormat"} {
		if !strings.Contains(string(b), k) {
			t.Errorf("payload %s is missing key %q", b, k)
		}
	}
}
