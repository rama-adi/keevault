package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"

	"github.com/ramaadi/keevault/apps/env-client/internal/protocol"
	"github.com/ramaadi/keevault/apps/env-client/internal/run"
	"github.com/ramaadi/keevault/apps/env-client/internal/vaultcrypto"
)

// maxFrameBytes is the protocol's frame limit, which the server enforces on
// the way in. The client agrees with it rather than with the plaintext
// arithmetic of 256 secrets at 64 KiB each: what travels is ciphertext, and a
// larger frame is something the server would never have sent.
const maxFrameBytes = 1 << 20

// readLimit leaves 64 KiB of slack above the protocol limit so a frame that is
// only slightly too large is read and reported as a protocol error rather than
// as a torn connection. Anything past that is cut off by the transport.
const readLimit = maxFrameBytes + 64<<10

const (
	writeTimeout = 15 * time.Second
	pingInterval = 20 * time.Second
	pingTimeout  = 10 * time.Second
	bootNonceLen = 16
)

// Session runs one boot from hello to exec.
type Session struct {
	cfg      Config
	log      *Logger
	endpoint string

	signPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey
	encPriv  *ecdh.PrivateKey
	clientFP string

	bootID   string
	secrets  []run.Secret
	acked    bool
	consumed bool

	// approvedEnvironmentID and approvedDigest pin the first accepted
	// boot.approved so a redelivery on resume cannot silently swap the
	// environment or the payload out from under an already-accepted boot.
	approvedEnvironmentID string
	approvedDigest        string
}

// New validates the configuration and generates the two ephemeral keypairs.
func New(cfg Config) (*Session, error) {
	cfg.applyDefaults()
	if cfg.Logger == nil {
		return nil, exitf(ExitConfig, "logger is required")
	}
	if len(cfg.Command) == 0 {
		return nil, exitf(ExitConfig, "no command configured; define command in keevault.json")
	}
	if _, err := vaultcrypto.ParseBootstrapToken(cfg.Token); err != nil {
		return nil, exitf(ExitConfig, "VAULT_BOOTSTRAP_TOKEN: %v", err)
	}
	endpoint, err := NormalizeURL(cfg.URL)
	if err != nil {
		return nil, exitf(ExitConfig, "%v", err)
	}
	if cfg.Environ == nil {
		cfg.Environ = os.Environ()
	}
	claim, err := executableClaim()
	if err != nil {
		cfg.Logger.Warnf("client executable SHA-256 unavailable; reporting version and platform only")
	}
	cfg.Claims.Client = &claim
	signPub, signPriv, err := vaultcrypto.GenerateEd25519()
	if err != nil {
		return nil, exitf(ExitProtocol, "%v", err)
	}
	encPriv, err := vaultcrypto.GenerateX25519()
	if err != nil {
		return nil, exitf(ExitProtocol, "%v", err)
	}
	clientFP, err := vaultcrypto.Fingerprint(encPriv.PublicKey().Bytes())
	if err != nil {
		return nil, exitf(ExitProtocol, "%v", err)
	}
	return &Session{
		cfg:      cfg,
		log:      cfg.Logger,
		endpoint: endpoint,
		signPub:  signPub,
		signPriv: signPriv,
		encPriv:  encPriv,
		clientFP: clientFP,
	}, nil
}

// Run drives the session. It returns nil only if Exec returned nil, which the
// real Exec never does.
func (s *Session) Run(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, s.cfg.PendingTimeout)
	defer cancel()
	defer s.wipeKeys()

	for attempt := 0; ; attempt++ {
		err := s.connect(ctx)
		if err == nil {
			return s.launch()
		}
		var exit *ExitError
		if errors.As(err, &exit) {
			return err
		}
		if ctx.Err() != nil {
			return exitf(ExitExpired, "boot did not complete within %s", s.cfg.PendingTimeout)
		}
		delay := s.backoff(attempt)
		s.log.Infof("reconnecting")
		s.log.Debugf("connection lost, retrying in %s: %v", delay.Round(time.Millisecond), err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return exitf(ExitExpired, "boot did not complete within %s", s.cfg.PendingTimeout)
		case <-timer.C:
		}
	}
}

// backoff returns the delay before retry number attempt, doubling from
// BackoffMin to BackoffMax with full jitter.
func (s *Session) backoff(attempt int) time.Duration {
	d := s.cfg.BackoffMin
	for i := 0; i < attempt && d < s.cfg.BackoffMax; i++ {
		d *= 2
	}
	if d > s.cfg.BackoffMax {
		d = s.cfg.BackoffMax
	}
	span := int64(d - s.cfg.BackoffMin)
	if span <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return d
	}
	return s.cfg.BackoffMin + time.Duration(n.Int64())
}

func (s *Session) connect(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+s.cfg.Token)

	dialCtx, cancelDial := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	conn, resp, err := websocket.Dial(dialCtx, s.endpoint, &websocket.DialOptions{HTTPHeader: header})
	cancelDial()
	if err != nil {
		if resp != nil {
			if fatal := handshakeExit(resp.StatusCode); fatal != nil {
				return fatal
			}
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(readLimit)

	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()
	go s.keepalive(connCtx, conn)

	if err := s.handshake(connCtx, conn); err != nil {
		return err
	}
	return s.loop(connCtx, conn)
}

func handshakeExit(status int) *ExitError {
	switch {
	case status == http.StatusTooManyRequests, status >= 500:
		return nil
	case status == http.StatusUnauthorized:
		return exitf(ExitProtocol, "vault rejected the bootstrap token")
	case status == http.StatusForbidden:
		return exitf(ExitProtocol, "vault refused the connection, check the token policy and source address")
	case status >= 400:
		return exitf(ExitProtocol, "vault upgrade failed with status %d", status)
	default:
		return nil
	}
}

func (s *Session) handshake(ctx context.Context, conn *websocket.Conn) error {
	if s.bootID == "" {
		return s.sendHello(ctx, conn)
	}
	return s.sendResume(ctx, conn)
}

func (s *Session) sendHello(ctx context.Context, conn *websocket.Conn) error {
	nonce, err := vaultcrypto.RandomBytes(bootNonceLen)
	if err != nil {
		return exitf(ExitProtocol, "%v", err)
	}
	evidence := s.cfg.Evidence
	if evidence == nil {
		evidence = []protocol.Evidence{}
	}
	hello := protocol.Hello{
		Type:                protocol.TypeHello,
		Protocol:            protocol.Version,
		BootNonce:           vaultcrypto.EncodeB64u(nonce),
		SigningPublicKey:    vaultcrypto.EncodeB64u(s.signPub),
		EncryptionPublicKey: vaultcrypto.EncodeB64u(s.encPriv.PublicKey().Bytes()),
		Claims:              s.cfg.Claims,
		Evidence:            evidence,
	}
	return s.send(ctx, conn, hello)
}

func (s *Session) sendResume(ctx context.Context, conn *websocket.Conn) error {
	return s.send(ctx, conn, protocol.Resume{
		Type:     protocol.TypeResume,
		Protocol: protocol.Version,
		BootID:   s.bootID,
	})
}

func (s *Session) send(ctx context.Context, conn *websocket.Conn, m protocol.Message) error {
	frame, err := protocol.Encode(m)
	if err != nil {
		return exitf(ExitProtocol, "%v", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, frame); err != nil {
		return fmt.Errorf("write %s: %w", m.MessageType(), err)
	}
	return nil
}

func (s *Session) keepalive(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				conn.CloseNow()
				return
			}
		}
	}
}

func (s *Session) loop(ctx context.Context, conn *websocket.Conn) error {
	for {
		frame, msg, err := s.read(ctx, conn)
		if err != nil {
			return s.classifyRead(err)
		}
		switch m := msg.(type) {
		case protocol.Pending:
			s.bootID = m.BootID
			s.log.Infof("boot request created: %s", m.BootID)
			s.log.Infof("waiting for approval")
		case protocol.Challenge:
			if err := s.answerChallenge(ctx, conn, m); err != nil {
				return err
			}
		case protocol.Resumed:
			if m.Status == protocol.StatusConsumed {
				s.log.Infof("approval already acknowledged")
				return exitf(ExitExpired, "boot already consumed; start a new boot")
			}
			s.log.Debugf("session resumed in state %s", m.Status)
		case protocol.Approved:
			if err := s.handleApproved(ctx, conn, frame, m); err != nil {
				return err
			}
		case protocol.Consumed:
			s.consumed = true
			conn.Close(websocket.StatusNormalClosure, "")
			return nil
		case protocol.Declined:
			return exitf(ExitDeclined, "boot declined by an administrator%s", reasonSuffix(m.Reason))
		case protocol.Expired:
			return exitf(ExitExpired, "boot expired before it was approved")
		case protocol.Canceled:
			return exitf(ExitExpired, "boot canceled%s", reasonSuffix(m.Reason))
		case protocol.Error:
			return s.protocolError(m)
		default:
			return exitf(ExitProtocol, "unexpected message %s", msg.MessageType())
		}
	}
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

func (s *Session) protocolError(m protocol.Error) error {
	switch m.Code {
	case protocol.CloseRateLimited:
		return fmt.Errorf("vault rate limited this client: %s", m.Message)
	case protocol.CloseTerminal:
		return exitf(ExitExpired, "boot is no longer usable: %s", m.Message)
	default:
		return exitf(ExitProtocol, "vault error %d: %s", m.Code, m.Message)
	}
}

func (s *Session) read(ctx context.Context, conn *websocket.Conn) ([]byte, protocol.Message, error) {
	kind, frame, err := conn.Read(ctx)
	if err != nil {
		return nil, nil, err
	}
	if kind != websocket.MessageText {
		return nil, nil, exitf(ExitProtocol, "vault sent a binary frame")
	}
	if len(frame) > maxFrameBytes {
		return nil, nil, exitf(ExitProtocol, "vault sent a frame of %d bytes, over the %d byte protocol limit", len(frame), maxFrameBytes)
	}
	msg, err := protocol.Decode(frame)
	if err != nil {
		return nil, nil, exitf(ExitProtocol, "%v", err)
	}
	return frame, msg, nil
}

// classifyRead decides whether a read failure ends the boot or triggers a
// reconnect.
func (s *Session) classifyRead(err error) error {
	var exit *ExitError
	if errors.As(err, &exit) {
		return err
	}
	if errors.Is(err, websocket.ErrMessageTooBig) {
		return exitf(ExitProtocol, "vault sent a frame over the %d byte protocol limit", maxFrameBytes)
	}
	status := websocket.CloseStatus(err)
	switch status {
	case -1:
		return err
	case websocket.StatusNormalClosure:
		if s.acked {
			s.consumed = true
			return nil
		}
		return fmt.Errorf("vault closed the connection: %w", err)
	case protocol.CloseTerminal:
		return exitf(ExitExpired, "vault closed the connection: the boot is terminal")
	case protocol.CloseRateLimited:
		return fmt.Errorf("vault rate limited this client: %w", err)
	case protocol.CloseBadToken:
		return exitf(ExitProtocol, "vault rejected the bootstrap token")
	case protocol.CloseForbidden:
		return exitf(ExitProtocol, "vault refused the connection, check the token policy and source address")
	case protocol.CloseProtocolError, protocol.CloseUnknownBoot, protocol.CloseConflict:
		return exitf(ExitProtocol, "vault closed the connection with code %d", int(status))
	default:
		return fmt.Errorf("connection closed: %w", err)
	}
}

func (s *Session) answerChallenge(ctx context.Context, conn *websocket.Conn, m protocol.Challenge) error {
	if s.bootID == "" {
		s.bootID = m.BootID
	}
	if m.BootID != s.bootID {
		return exitf(ExitProtocol, "challenge is for a different boot request")
	}
	signature := vaultcrypto.SignResume(s.signPriv, s.bootID, m.Challenge)
	return s.send(ctx, conn, protocol.ChallengeResponse{
		Type:      protocol.TypeChallengeResponse,
		BootID:    s.bootID,
		Signature: vaultcrypto.EncodeB64u(signature),
	})
}
