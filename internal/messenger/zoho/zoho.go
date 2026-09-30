// Package zoho implements a listmonk manager.Messenger that sends campaign
// e-mails through the Zoho Mail REST API (accounts.zoho.in / mail.zoho.in)
// using OAuth2 refresh tokens.
//
// It sits alongside the existing SMTP `email` messenger and does not replace
// it. Transactional / system e-mails continue to flow over SMTP.
//
// Multiple independent Zoho accounts ("mailboxes") can be registered at once.
// The From address of each outgoing message selects which registered account
// sends it. Messages with a From address that has no matching account are
// rejected with an explicit error instead of being silently routed to an
// arbitrary account.
package zoho

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/knadh/listmonk/internal/utils"
	"github.com/knadh/listmonk/models"
	"golang.org/x/oauth2"
)

const (
	// MessengerName is the name this messenger registers under. Campaigns
	// select it by this name in the UI and API.
	MessengerName = "zoho"

	// DefaultAccountsHost is the Zoho India data-centre accounts host. The
	// documented OAuth and mail API endpoints both derive from it.
	DefaultAccountsHost = "accounts.zoho.in"

	// oauthTimeout bounds a single token request.
	oauthTimeout = 15 * time.Second

	// sendTimeout bounds a single send-mail API request.
	sendTimeout = 60 * time.Second

	// refreshWindow is how long before actual expiry a cached access token is
	// treated as expired, so we never put a token on the wire that is about to
	// die mid-request.
	refreshWindow = 60 * time.Second

	// defaultTokenLifetime is assumed when Zoho returns a token with no
	// expiry, so a token is never cached forever.
	defaultTokenLifetime = time.Hour
)

// Errors returned by this package. They are wrapped with %w so callers can use
// errors.Is. None of them ever embed tokens or secrets.
var (
	// ErrUnsupportedFrom is returned when a message's From address does not map
	// to any configured Zoho account.
	ErrUnsupportedFrom = errors.New("unsupported Zoho sender address")

	// ErrAttachmentsUnsupported is returned when a message carries attachments,
	// which this transport does not support. Failing loudly is deliberate:
	// silently dropping attachments would send incomplete mail.
	ErrAttachmentsUnsupported = errors.New("Zoho messenger does not support attachments")

	// ErrUnsupportedHeader is returned when a message carries a header that
	// cannot be represented in Zoho's send-mail API and is not one Zoho manages
	// itself.
	ErrUnsupportedHeader = errors.New("Zoho messenger cannot set this header")

	// ErrNoAccounts is returned when the messenger is constructed with no
	// usable accounts.
	ErrNoAccounts = errors.New("no Zoho accounts configured")
)

// zohoManagedHeaders are headers listmonk may set that Zoho's send-mail API
// cannot carry. Zoho manages unsubscribe handling itself per mailbox, so these
// are dropped with a warning rather than failing the send. Anything outside this
// set is a hard error.
var zohoManagedHeaders = map[string]bool{
	"list-unsubscribe":      true,
	"list-unsubscribe-post": true,
}

// Opt is the config for a single Zoho mailbox / OAuth client.
type Opt struct {
	// Name is the mailbox key this account serves, e.g. "contact". It is only
	// used for logging and error messages; routing is by From address.
	Name string `json:"name"`

	// FromAddress is the fixed sender address this account is allowed to send
	// as, e.g. contact@vireliastudio.one.
	FromAddress string `json:"from_address"`

	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	// RefreshToken is a long-lived Zoho OAuth refresh token. It is never logged
	// and never included in a returned error.
	RefreshToken string `json:"refresh_token"`

	// AccountID is the Zoho organisation/account ID used to build the mail API
	// path: /api/accounts/{accountId}/messages
	AccountID string `json:"account_id"`

	// ZohoAccountsHost is the accounts host for this client's data centre,
	// e.g. "accounts.zoho.in" (India), "accounts.zoho.com" (US),
	// "accounts.zoho.eu" (EU). Defaults to accounts.zoho.in.
	ZohoAccountsHost string `json:"zoho_accounts_host"`

	// MailHost is the mail API host, e.g. "mail.zoho.in". Defaults to
	// "mail." + the accounts host.
	MailHost string `json:"mail_host"`

	// OAuthTokenURL overrides the token endpoint. Defaults to
	// https://<zoho_accounts_host>/oauth/v2/token.
	OAuthTokenURL string `json:"oauth_token_url"`

	// APIVersion is the mail API version path segment. Defaults to "v1".
	APIVersion string `json:"api_version"`
}

// Account is a configured Zoho mailbox plus its cached OAuth access token.
//
// An Account is safe for concurrent use: access tokens are fetched at most one
// at a time and shared across every goroutine sending through this account, so
// a burst of sends produces one token request, not one per message.
type Account struct {
	// key is the lowercased From address this account serves.
	key string

	opt Opt

	// conf is the OAuth client config used to exchange the refresh token. The
	// access token is set explicitly per request, so the shared HTTP transport
	// stays pooled and connection reuse is preserved.
	conf *oauth2.Config

	// tokHTTP performs token requests only.
	tokHTTP *http.Client

	mut     sync.Mutex
	tok     *oauth2.Token
	expires time.Time
}

// Messenger is the Zoho Mail API campaign messenger.
type Messenger struct {
	name     string
	accounts map[string]*Account
	order    []string // account keys, for stable error messages

	client *http.Client

	// retries is the max number of *extra* attempts for transient failures.
	retries int

	// backoff is the base delay for exponential backoff between retries.
	backoff time.Duration

	// warnOnce tracks headers already warned about, to avoid log spam.
	warnOnce map[string]bool
	warnMut  sync.Mutex

	log *log.Logger
}

// New returns a Zoho Mail API messenger for the given accounts.
//
// Every account is validated up front, so an invalid account fails construction
// rather than failing later on the first campaign send.
func New(accounts []Opt, logger *log.Logger) (*Messenger, error) {
	return NewWithClient(accounts, nil, logger)
}

// NewWithClient is New with an explicit HTTP client for send-mail API requests.
// Passing a client lets tests point at an httptest server.
func NewWithClient(accounts []Opt, client *http.Client, logger *log.Logger) (*Messenger, error) {
	if client == nil {
		client = &http.Client{Timeout: sendTimeout}
	}

	m := &Messenger{
		name:     MessengerName,
		accounts: make(map[string]*Account, len(accounts)),
		client:   client,
		retries:  3,
		backoff:  500 * time.Millisecond,
		warnOnce: make(map[string]bool),
		log:      logger,
	}

	for _, o := range accounts {
		a, err := newAccount(o)
		if err != nil {
			return nil, err
		}

		if _, ok := m.accounts[a.key]; ok {
			return nil, fmt.Errorf("duplicate Zoho account for sender %q", a.key)
		}

		m.accounts[a.key] = a
		m.order = append(m.order, a.key)
	}

	if len(m.accounts) == 0 {
		return nil, ErrNoAccounts
	}

	return m, nil
}

// newAccount validates a single account's config and prepares its OAuth client.
// Errors it returns name the account and the offending *field*, never any
// secret value.
func newAccount(o Opt) (*Account, error) {
	name := o.Name
	if name == "" {
		name = MessengerName
	}

	for _, f := range []struct {
		key string
		val string
	}{
		{"from_address", o.FromAddress},
		{"client_id", o.ClientID},
		{"client_secret", o.ClientSecret},
		{"refresh_token", o.RefreshToken},
		{"account_id", o.AccountID},
	} {
		if strings.TrimSpace(f.val) == "" {
			return nil, fmt.Errorf("zoho account %q: missing required config %q", name, f.key)
		}
	}

	key := utils.ParseEmailAddress(o.FromAddress)
	if key == "" {
		return nil, fmt.Errorf("zoho account %q: invalid from_address %q", name, truncate(o.FromAddress))
	}

	hosts, err := resolveHosts(o)
	if err != nil {
		return nil, fmt.Errorf("zoho account %q: %w", name, err)
	}

	tokenURL := o.OAuthTokenURL
	if tokenURL == "" {
		tokenURL = "https://" + hosts.accounts + "/oauth/v2/token"
	}

	if o.APIVersion == "" {
		o.APIVersion = "v1"
	}
	if strings.ContainsAny(o.APIVersion, "/?#") {
		return nil, fmt.Errorf("zoho account %q: invalid api_version", name)
	}

	a := &Account{key: key, opt: o}

	// Refresh tokens are exchanged using the confidential-client flow: Zoho
	// expects client_id / client_secret / refresh_token in the POST body. The
	// client_secret travels in that body and is never logged.
	a.conf = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scopes:       []string{"ZohoMail.messages.ALL"},
		Endpoint: oauth2.Endpoint{
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	a.tokHTTP = &http.Client{Timeout: oauthTimeout}

	// x/oauth2 reads the refresh token off the *previous* token, not off the
	// config. Seed one so the very first TokenSource() call performs a
	// "grant_type=refresh_token" exchange.
	a.tok = &oauth2.Token{RefreshToken: o.RefreshToken}

	return a, nil
}

// hosts holds the resolved per-datacentre hosts for an account.
type hosts struct {
	accounts string
	mail     string
}

// resolveHosts works out the accounts and mail hosts for an account, applying
// Zoho's data-centre defaults when they are not set explicitly.
func resolveHosts(o Opt) (hosts, error) {
	var h hosts

	switch {
	case o.OAuthTokenURL != "":
		u, err := url.Parse(o.OAuthTokenURL)
		if err != nil || u.Host == "" {
			return h, fmt.Errorf("invalid oauth_token_url %q", truncate(o.OAuthTokenURL))
		}
		h.accounts = u.Hostname()
	case o.ZohoAccountsHost != "":
		h.accounts = bareHost(o.ZohoAccountsHost)
	default:
		h.accounts = DefaultAccountsHost
	}

	if h.accounts == "" || strings.ContainsAny(h.accounts, " /") {
		return h, fmt.Errorf("invalid zoho_accounts_host %q", truncate(o.ZohoAccountsHost))
	}

	// accounts.zoho.in -> mail.zoho.in, accounts.zoho.eu -> mail.zoho.eu.
	if o.MailHost != "" {
		h.mail = bareHost(o.MailHost)
	} else if rest, ok := strings.CutPrefix(h.accounts, "accounts."); ok {
		h.mail = "mail." + rest
	} else {
		h.mail = "mail." + h.accounts
	}

	if h.mail == "" || strings.ContainsAny(h.mail, " /") {
		return h, fmt.Errorf("invalid mail_host %q", truncate(o.MailHost))
	}

	return h, nil
}

// bareHost strips any scheme or trailing slash from a host string.
func bareHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "https://"), "http://")
	return strings.TrimRight(s, "/")
}

// Name returns the messenger's name.
func (m *Messenger) Name() string { return m.name }

// Flush is a no-op. Each send is issued synchronously by Push, so there is no
// buffered queue to drain.
func (m *Messenger) Flush() error { return nil }

// Close releases idle connections held by the HTTP clients.
func (m *Messenger) Close() error {
	if m.client != nil {
		m.client.CloseIdleConnections()
	}
	for _, a := range m.accounts {
		a.mut.Lock()
		if a.tokHTTP != nil {
			a.tokHTTP.CloseIdleConnections()
		}
		a.mut.Unlock()
	}
	return nil
}

// accountFor returns the account registered for the given From address.
func (m *Messenger) accountFor(from string) (*Account, error) {
	key := utils.ParseEmailAddress(from)
	if key == "" {
		return nil, fmt.Errorf("%w: %q is not a valid sender address", ErrUnsupportedFrom, truncate(from))
	}

	a, ok := m.accounts[key]
	if !ok {
		return nil, fmt.Errorf("%w: %q. Configured Zoho senders: %s",
			ErrUnsupportedFrom, truncate(key), strings.Join(m.order, ", "))
	}

	return a, nil
}

// Push sends a message through the Zoho Mail API using the account registered
// for the message's From address.
func (m *Messenger) Push(msg models.Message) error {
	a, err := m.accountFor(msg.From)
	if err != nil {
		return err
	}

	// Attachments are not implemented. Refuse explicitly rather than sending an
	// e-mail that silently lost its files.
	if len(msg.Attachments) > 0 {
		return fmt.Errorf("%w (message to %s)", ErrAttachmentsUnsupported, msg.To)
	}

	payload, err := m.buildPayload(msg)
	if err != nil {
		return err
	}

	return m.send(a, payload)
}

// splitAddr splits an RFC 5322 address into its bare e-mail address and its
// optional display name.
func splitAddr(s string) (addr, name string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	lt, gt := strings.LastIndex(s, "<"), strings.LastIndex(s, ">")
	if lt != -1 && gt > lt {
		name = strings.TrimSpace(s[:lt])
		addr = strings.TrimSpace(s[lt+1 : gt])
		// Strip surrounding quotes and unescape a quoted display name.
		name = strings.Trim(name, `"`)
		if unescaped, err := url.PathUnescape(name); err == nil {
			name = unescaped
		}
		return addr, name
	}

	return s, ""
}

// addrObj builds a Zoho address object.
func addrObj(s string) (map[string]string, bool) {
	a, n := splitAddr(s)
	if a == "" {
		return nil, false
	}

	o := map[string]string{"address": a}
	if n != "" {
		o["displayName"] = n
	}
	return o, true
}

// addrObjs maps a list of Listmonk addresses into Zoho address objects.
func addrObjs(in []string) []map[string]string {
	out := make([]map[string]string, 0, len(in))
	for _, s := range in {
		if o, ok := addrObj(s); ok {
			out = append(out, o)
		}
	}
	return out
}

// recipientSet splits message headers into envelope recipients Zoho can carry
// and reports any header it cannot represent.
func splitHeaders(h map[string][]string) (cc, bcc []string, replyTo string, err error) {
	for k, v := range h {
		lk := strings.ToLower(k)

		switch {
		case lk == "cc":
			cc = appendAll(cc, v)
		case lk == "bcc":
			bcc = appendAll(bcc, v)
		case lk == "reply-to":
			if len(v) > 0 {
				replyTo = strings.TrimSpace(v[0])
			}
		}
	}

	// Any header left over is not representable in Zoho's send-mail payload.
	// Zoho-managed unsubscribe headers are dropped with a warning (Zoho applies
	// its own per-mailbox unsubscribe policy); anything else is a hard error so
	// we never claim to have sent something we did not.
	for k := range h {
		if zohoManagedHeaders[strings.ToLower(k)] {
			continue
		}

		switch strings.ToLower(k) {
		case "cc", "bcc", "reply-to":
			continue
		}

		return nil, nil, "", fmt.Errorf("%w: %q (the Zoho send-mail API has no arbitrary header field)", ErrUnsupportedHeader, k)
	}

	return cc, bcc, replyTo, nil
}

// appendAll splits comma-separated header values into a flat recipient list.
func appendAll(dst []string, vals []string) []string {
	for _, val := range vals {
		for _, part := range strings.Split(val, ",") {
			if p := strings.TrimSpace(part); p != "" {
				dst = append(dst, p)
			}
		}
	}
	return dst
}

// buildPayload maps a listmonk models.Message onto the Zoho send-mail payload.
func (m *Messenger) buildPayload(msg models.Message) ([]byte, error) {
	cc, bcc, replyTo, err := splitHeaders(msg.Headers)
	if err != nil {
		return nil, err
	}

	m.warnManagedHeaders(msg.Headers)

	fromAddr, fromName := splitAddr(msg.From)
	if fromAddr == "" {
		return nil, fmt.Errorf("%w: empty sender address", ErrUnsupportedFrom)
	}

	p := map[string]any{
		"fromAddress": map[string]string{"address": fromAddr},
		"subject":     msg.Subject,
		"toAddress":   addrObjs(msg.To),
	}

	if fromName != "" {
		p["fromAddress"].(map[string]string)["displayName"] = fromName
	}

	if o := addrObjs(cc); len(o) > 0 {
		p["ccAddress"] = o
	}
	if o := addrObjs(bcc); len(o) > 0 {
		p["bccAddress"] = o
	}
	if o, ok := addrObj(replyTo); ok {
		p["replyToAddress"] = o
	}

	// Body. Zoho's send-mail API takes a single `content` string plus a
	// `mailFormat` of "html" or "text"; it cannot carry an HTML body and a
	// plain-text alternative in the same call. HTML wins when present, matching
	// what a mail client renders first over SMTP. The plain-text alternative is
	// therefore not sent -- this is a documented Zoho API limitation, not a bug.
	switch {
	case len(msg.Body) > 0:
		p["mailFormat"] = "html"
		p["content"] = string(msg.Body)
	case len(msg.AltBody) > 0:
		p["mailFormat"] = "text"
		p["content"] = string(msg.AltBody)
	default:
		return nil, errors.New("zoho messenger: message has an empty body")
	}

	return json.Marshal(p)
}

// warnManagedHeaders logs, once per header, that Zoho handles it itself.
func (m *Messenger) warnManagedHeaders(h map[string][]string) {
	if m.log == nil {
		return
	}

	for k := range h {
		if !zohoManagedHeaders[strings.ToLower(k)] {
			continue
		}

		m.warnMut.Lock()
		seen := m.warnOnce[k]
		m.warnOnce[k] = true
		m.warnMut.Unlock()

		if !seen {
			m.log.Printf("zoho: header %q is not supported by the Zoho send-mail API and is not sent; "+
				"configure unsubscribe handling in the Zoho Mailbox instead", k)
		}
	}
}

// send posts the payload to Zoho, retrying transient failures with bounded
// exponential backoff, and refreshing the access token once on a 401.
func (m *Messenger) send(a *Account, payload []byte) error {
	endpoint := fmt.Sprintf("https://%s/api/accounts/%s/%s/messages",
		a.host(), url.PathEscape(a.opt.AccountID), a.opt.APIVersion)

	var (
		lastErr     error
		refreshDone bool
	)

	for attempt := 0; attempt <= m.retries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(m.backoff << (attempt - 1)); err != nil {
				return err
			}
		}

		status, body, err := m.doSend(a, endpoint, payload)
		if err != nil {
			// Network-level failure. Treat as transient and retry.
			lastErr = fmt.Errorf("zoho send request failed: %w", err)
			m.debugf("send attempt %d for %s failed: %v", attempt+1, a.label(), err)
			continue
		}

		switch {
		case status == http.StatusUnauthorized:
			// The token was rejected or expired. Drop the cached token so the
			// next attempt obtains a fresh one, then retry exactly once.
			if refreshDone {
				return fmt.Errorf("zoho API rejected the message after token refresh (401): %s", apiErrMsg(body))
			}

			a.invalidate()
			refreshDone = true
			lastErr = errors.New("zoho API rejected the access token (401)")
			m.debugf("API returned 401 for %s, refreshing access token and retrying once", a.label())
			continue

		case status == http.StatusTooManyRequests, status >= 500:
			// Transient: rate limited or server-side. Retry.
			lastErr = fmt.Errorf("zoho API returned transient status %d: %s", status, apiErrMsg(body))
			m.debugf("API returned %d for %s on attempt %d, retrying", status, a.label(), attempt+1)
			continue

		case status >= 400:
			// Permanent 4xx. Retrying will not help.
			return fmt.Errorf("zoho API rejected the message (status %d): %s", status, apiErrMsg(body))

		default:
			return nil
		}
	}

	return fmt.Errorf("zoho send failed after %d attempt(s): %w", m.retries+1, lastErr)
}

// doSend performs a single authenticated send-mail API request.
func (m *Messenger) doSend(a *Account, endpoint string, payload []byte) (int, []byte, error) {
	tok, err := a.accessToken()
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	setZohoAuth(req, tok.AccessToken)

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, nil
}

// setZohoAuth applies Zoho's custom auth header scheme.
//
// Zoho's Mail API expects "Zoho-oauthtoken <access_token>" -- NOT
// "Bearer <access_token>". Using Bearer here is the most common cause of a 401.
func setZohoAuth(req *http.Request, accessToken string) {
	req.Header.Set("Authorization", "Zoho-oauthtoken "+accessToken)
}

// host returns the mail API host for this account.
func (a *Account) host() string {
	h, err := resolveHosts(a.opt)
	if err != nil {
		return DefaultAccountsHost
	}
	return h.mail
}

// accessToken returns a valid cached access token, fetching or refreshing it
// only when needed. Concurrent callers serialise on the mutex, so a burst of
// concurrent sends results in one token request rather than one per message.
func (a *Account) accessToken() (*oauth2.Token, error) {
	a.mut.Lock()
	defer a.mut.Unlock()

	// Valid cached token: reuse it. This is what keeps us from requesting a new
	// token for every e-mail.
	if a.tok != nil && a.tok.AccessToken != "" && a.tok.Valid() && time.Now().Add(refreshWindow).Before(a.expires) {
		return a.tok, nil
	}

	tok, err := a.conf.TokenSource(a.tokenCtx(), a.tok).Token()
	if err != nil {
		// The raw error from the token source can embed the client secret, the
		// refresh token or the returned token. Never surface it verbatim.
		return nil, fmt.Errorf("zoho account %q: could not obtain an access token "+
			"(the refresh token may be invalid, revoked, or lack the ZohoMail.messages.ALL scope)", a.label())
	}

	if tok == nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("zoho account %q: Zoho returned an empty access token", a.label())
	}

	// Zoho may rotate the refresh token, and may omit it from the response when
	// it does not. Keep the previous one in that case so the next refresh works.
	if tok.RefreshToken == "" {
		tok.RefreshToken = a.tok.RefreshToken
	}

	if tok.Expiry.IsZero() {
		tok.Expiry = time.Now().Add(defaultTokenLifetime)
	}

	a.tok = tok
	a.expires = tok.Expiry

	return tok, nil
}

// tokenCtx returns the context used for token requests, bound to the account's
// dedicated token HTTP client.
func (a *Account) tokenCtx() context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, a.tokHTTP)
}

// invalidate drops the cached access token so the next accessToken call
// refreshes it. The refresh token is preserved -- only the short-lived access
// token is discarded.
func (a *Account) invalidate() {
	a.mut.Lock()
	defer a.mut.Unlock()

	rt := ""
	if a.tok != nil {
		rt = a.tok.RefreshToken
	}

	a.tok = &oauth2.Token{RefreshToken: rt}
	a.expires = time.Time{}
}

// label returns a non-secret identifier for the account, safe for logs.
func (a *Account) label() string {
	if a.opt.Name != "" {
		return a.opt.Name
	}
	return a.key
}

// debugf logs a one-line, secret-free diagnostic.
func (m *Messenger) debugf(format string, args ...any) {
	if m.log == nil {
		return
	}
	m.log.Printf("zoho: "+format, args...)
}

// apiErrMsg extracts a human-readable, non-secret error message from a Zoho
// error response body.
func apiErrMsg(body []byte) string {
	if len(body) == 0 {
		return "(empty response body)"
	}

	var r struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details string `json:"details"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &r); err == nil {
		if r.Error.Message != "" {
			msg := r.Error.Message
			if r.Error.Code != "" {
				msg = r.Error.Code + ": " + msg
			}
			if r.Error.Details != "" {
				msg += " (" + r.Error.Details + ")"
			}
			return msg
		}
		if r.Message != "" {
			if r.Code != "" {
				return r.Code + ": " + r.Message
			}
			return r.Message
		}
	}

	// Malformed or non-JSON body: return a bounded snippet.
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	if s == "" {
		return "(empty response body)"
	}
	return s
}

// truncate bounds a string for inclusion in an error message.
func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// sleepCtx waits for d to elapse.
func sleepCtx(d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	<-t.C
	return nil
}
