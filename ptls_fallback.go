package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

const maxFallbackSessions = 2048

type ptlsFallbackRelayer struct {
	serverConn rawConn
	config     PTLSFallbackConfig
	logger     utils.Logger
	network    string
	targetAddr string
	qpsLimiter *ptlsTokenBucket
	qosLimit   int64
	timeout    time.Duration

	mu       sync.RWMutex
	sessions map[string]*ptlsUDPSession
	ctx      context.Context
	cancel   context.CancelFunc
}

func newPTLSFallbackRelayer(conn rawConn, config PTLSFallbackConfig, logger utils.Logger) *ptlsFallbackRelayer {
	qps := config.QPS
	if qps <= 0 {
		qps = 5
	}
	burst := qps * 2
	if burst < 5 {
		burst = 5
	}

	qosBytes, _ := parseBandwidth(config.QoS)
	if qosBytes <= 0 {
		qosBytes = 50 * 1024 // 默认 50 KB/s
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	network, address, err := resolveUDPTarget(config.Server, config.Port)
	if err != nil {
		if logger != nil {
			logger.Errorf("ptls fallback: resolve target %s:%d failed: %s", config.Server, config.Port, err)
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ptlsFallbackRelayer{
		serverConn: conn,
		config:     config,
		logger:     logger,
		network:    network,
		targetAddr: address,
		qpsLimiter: newPTLSTokenBucket(float64(qps), float64(burst)),
		qosLimit:   qosBytes,
		timeout:    timeout,
		sessions:   make(map[string]*ptlsUDPSession),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (r *ptlsFallbackRelayer) HasSession(addr net.Addr) bool {
	if r == nil || addr == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sessions[addr.String()]
	return ok
}

func (r *ptlsFallbackRelayer) HandlePacket(data []byte, remoteAddr net.Addr, info packetInfo) {
	if r == nil || len(data) == 0 || remoteAddr == nil {
		return
	}
	key := remoteAddr.String()

	r.mu.RLock()
	sess, ok := r.sessions[key]
	r.mu.RUnlock()

	if ok {
		if sess.isClosed() {
			return
		}
		sess.setOOB(info.OOB())
		pkt := make([]byte, len(data))
		copy(pkt, data)
		select {
		case sess.queue <- pkt:
		default:
			// 队列已满，丢弃以防内存膨胀
		}
		return
	}

	// 新会话准入检查：QPS 令牌桶限流
	if r.qpsLimiter != nil && !r.qpsLimiter.Allow() {
		if r.logger != nil && r.logger.Debug() {
			r.logger.Debugf("ptls fallback: QPS rate limit exceeded for %s", remoteAddr)
		}
		return
	}

	r.mu.Lock()
	if len(r.sessions) >= maxFallbackSessions {
		r.mu.Unlock()
		return
	}
	if existing, exists := r.sessions[key]; exists {
		r.mu.Unlock()
		if existing.isClosed() {
			return
		}
		existing.setOOB(info.OOB())
		pkt := make([]byte, len(data))
		copy(pkt, data)
		select {
		case existing.queue <- pkt:
		default:
		}
		return
	}

	pkt := make([]byte, len(data))
	copy(pkt, data)

	sess = r.newSession(key, remoteAddr, info.OOB(), pkt)
	r.sessions[key] = sess
	r.mu.Unlock()

	go sess.run(r)
}

func (r *ptlsFallbackRelayer) removeSession(key string) {
	r.mu.Lock()
	delete(r.sessions, key)
	r.mu.Unlock()
}

func (r *ptlsFallbackRelayer) Close() {
	if r == nil {
		return
	}
	r.cancel()
	r.mu.Lock()
	sessions := make([]*ptlsUDPSession, 0, len(r.sessions))
	for _, sess := range r.sessions {
		sessions = append(sessions, sess)
	}
	r.sessions = make(map[string]*ptlsUDPSession)
	r.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
}

type ptlsUDPSession struct {
	key         string
	clientAddr  net.Addr
	targetConn  net.Conn
	queue       chan []byte
	oob         []byte
	oobMu       sync.RWMutex
	connMu      sync.Mutex
	closed      bool
	uplinkQoS   *ptlsBandwidthLimiter
	downlinkQoS *ptlsBandwidthLimiter
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	relayer     *ptlsFallbackRelayer
}

func (r *ptlsFallbackRelayer) newSession(key string, clientAddr net.Addr, oob []byte, initialPkt []byte) *ptlsUDPSession {
	sessCtx, sessCancel := context.WithTimeout(r.ctx, r.timeout)
	sess := &ptlsUDPSession{
		key:         key,
		clientAddr:  clientAddr,
		queue:       make(chan []byte, 64),
		uplinkQoS:   newPTLSBandwidthLimiter(r.qosLimit),
		downlinkQoS: newPTLSBandwidthLimiter(r.qosLimit),
		ctx:         sessCtx,
		cancel:      sessCancel,
		relayer:     r,
	}
	sess.setOOB(oob)
	if len(initialPkt) > 0 {
		sess.queue <- initialPkt
	}
	return sess
}

func (s *ptlsUDPSession) isClosed() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.closed
}

func (s *ptlsUDPSession) setOOB(oob []byte) {
	if len(oob) == 0 {
		return
	}
	s.oobMu.Lock()
	if len(s.oob) != len(oob) {
		s.oob = make([]byte, len(oob))
	}
	copy(s.oob, oob)
	s.oobMu.Unlock()
}

func (s *ptlsUDPSession) getOOB() []byte {
	s.oobMu.RLock()
	defer s.oobMu.RUnlock()
	if len(s.oob) == 0 {
		return nil
	}
	res := make([]byte, len(s.oob))
	copy(res, s.oob)
	return res
}

func (s *ptlsUDPSession) run(r *ptlsFallbackRelayer) {
	dialer := net.Dialer{Timeout: r.timeout}
	targetConn, err := dialer.DialContext(s.ctx, r.network, r.targetAddr)
	if err != nil {
		if r.logger != nil && r.logger.Debug() {
			r.logger.Debugf("ptls fallback: dial target %s (%s) failed: %s", r.targetAddr, r.network, err)
		}
		s.close()
		return
	}

	s.connMu.Lock()
	if s.closed {
		s.connMu.Unlock()
		_ = targetConn.Close()
		return
	}
	s.targetConn = targetConn
	s.connMu.Unlock()

	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-s.ctx.Done():
			s.close()
		case <-ctxDone:
		}
	}()
	defer close(ctxDone)

	var wg sync.WaitGroup
	wg.Add(2)

	// 下行 Worker: Target -> Client
	go func() {
		defer wg.Done()
		defer s.close()
		buf := make([]byte, 65536)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				s.downlinkQoS.Wait(n)
				oob := s.getOOB()
				_, _ = r.serverConn.WritePacket(buf[:n], s.clientAddr, oob, 0, protocol.ECNUnsupported)
			}
		}
	}()

	// 上行 Worker: Client -> Target
	go func() {
		defer wg.Done()
		defer s.close()
		for {
			select {
			case <-s.ctx.Done():
				return
			case pkt, ok := <-s.queue:
				if !ok {
					return
				}
				s.uplinkQoS.Wait(len(pkt))
				_, err := targetConn.Write(pkt)
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
}

func (s *ptlsUDPSession) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.connMu.Lock()
		s.closed = true
		if s.targetConn != nil {
			_ = s.targetConn.SetDeadline(time.Now())
			_ = s.targetConn.Close()
		}
		s.connMu.Unlock()
		s.relayer.removeSession(s.key)
	})
}

func resolveUDPTarget(server string, port uint16) (string, string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", "", errors.New("ptls: fallback server not configured")
	}
	if strings.HasPrefix(server, "unix:") {
		return "unixgram", strings.TrimPrefix(server, "unix:"), nil
	}
	if strings.HasPrefix(server, "/") || strings.HasPrefix(server, "./") || strings.HasPrefix(server, "../") ||
		strings.HasSuffix(server, ".sock") || strings.HasSuffix(server, ".socket") {
		return "unixgram", server, nil
	}

	network := "udp"
	var address string
	if port > 0 {
		address = net.JoinHostPort(server, strconv.Itoa(int(port)))
	} else {
		if _, _, err := net.SplitHostPort(server); err == nil {
			address = server
		} else {
			address = net.JoinHostPort(server, "443")
		}
	}
	return network, address, nil
}

type ptlsTokenBucket struct {
	rate       float64
	burst      float64
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func newPTLSTokenBucket(rate float64, burst float64) *ptlsTokenBucket {
	return &ptlsTokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastUpdate: time.Now(),
	}
}

func (tb *ptlsTokenBucket) Allow() bool {
	if tb == nil {
		return true
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * tb.rate
		if tb.tokens > tb.burst {
			tb.tokens = tb.burst
		}
		tb.lastUpdate = now
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type ptlsBandwidthLimiter struct {
	bytesPerSec int64
	burst       int64
	tokens      int64
	lastUpdate  time.Time
	mu          sync.Mutex
}

func newPTLSBandwidthLimiter(bytesPerSec int64) *ptlsBandwidthLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := bytesPerSec * 2
	if burst < 65536 {
		burst = 65536
	}
	return &ptlsBandwidthLimiter{
		bytesPerSec: bytesPerSec,
		burst:       burst,
		tokens:      burst,
		lastUpdate:  time.Now(),
	}
}

func (b *ptlsBandwidthLimiter) Wait(n int) {
	if b == nil || b.bytesPerSec <= 0 || n <= 0 {
		return
	}
	b.mu.Lock()
	now := time.Now()
	if now.After(b.lastUpdate) {
		elapsed := now.Sub(b.lastUpdate).Seconds()
		b.tokens += int64(elapsed * float64(b.bytesPerSec))
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.lastUpdate = now
	}

	b.tokens -= int64(n)
	var sleepDuration time.Duration
	if b.tokens < 0 {
		deficit := -b.tokens
		delay := time.Duration(float64(deficit) / float64(b.bytesPerSec) * float64(time.Second))
		b.tokens = 0
		b.lastUpdate = b.lastUpdate.Add(delay)
		sleepDuration = b.lastUpdate.Sub(now)
	}
	b.mu.Unlock()

	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}

func parseBandwidth(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSuffix(s, "/sec")
	s = strings.TrimSuffix(s, "/s")
	s = strings.TrimSuffix(s, "ps")
	s = strings.TrimSuffix(s, "sec")

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "gib"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gib")
	case strings.HasSuffix(s, "gb"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gb")
	case strings.HasSuffix(s, "g"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "mib"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mib")
	case strings.HasSuffix(s, "mb"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "m"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "kib"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "kib")
	case strings.HasSuffix(s, "kb"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "kb")
	case strings.HasSuffix(s, "k"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "b"):
		multiplier = 1
		s = strings.TrimSuffix(s, "b")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("ptls: invalid bandwidth format: %s", s)
	}
	if val <= 0 {
		return 0, nil
	}
	return int64(val * float64(multiplier)), nil
}
