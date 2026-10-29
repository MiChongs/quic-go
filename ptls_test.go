package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/handshake"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Test Helpers & Mock Implementations
// -----------------------------------------------------------------------------

type testClientPTLSRand struct {
	mu   sync.Mutex
	psk  [32]byte
	dcid []byte
}

func newTestClientPTLSRand(psk [32]byte) *testClientPTLSRand {
	return &testClientPTLSRand{psk: psk}
}

func (r *testClientPTLSRand) SetDestinationConnectionID(dcid []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dcid = append([]byte(nil), dcid...)
}

func (r *testClientPTLSRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) == 32 && len(r.dcid) > 0 {
		mac := hmac.New(sha256.New, r.psk[:])
		mac.Write(r.dcid)
		tag := mac.Sum(nil)
		copy(p, tag[:32])
		return 32, nil
	}
	return rand.Read(p)
}

type testServerGatekeeper struct {
	pskList  [][32]byte
	fbConfig PTLSFallbackConfig
	allowSNI func(sni string) bool
}

func (g *testServerGatekeeper) Read(p []byte) (int, error) {
	return rand.Read(p)
}

func (g *testServerGatekeeper) VerifyInitial(dcid []byte, random []byte, rawPacket []byte, remoteAddr net.Addr) (bool, error) {
	if len(random) != 32 {
		return false, nil
	}
	for _, psk := range g.pskList {
		mac := hmac.New(sha256.New, psk[:])
		mac.Write(dcid)
		expected := mac.Sum(nil)
		if hmac.Equal(random, expected) {
			return true, nil
		}
	}
	return false, nil
}

func (g *testServerGatekeeper) GetFallbackConfig() PTLSFallbackConfig {
	return g.fbConfig
}

func (g *testServerGatekeeper) CheckSNI(sni string) bool {
	if g.allowSNI != nil {
		return g.allowSNI(sni)
	}
	return true
}

func generateTestCertificates(t *testing.T) (*tls.Config, *tls.Config) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"PTLS Test Suite"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "ptls.test.org"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	certPool.AddCert(parsed)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"ptls-e2e"},
	}

	clientTLS := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
		NextProtos: []string{"ptls-e2e"},
	}

	return serverTLS, clientTLS
}

func buildClientHelloPayload(random []byte, sni string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03) // TLS 1.2 legacy version
	if len(random) == 32 {
		body = append(body, random...)
	} else {
		body = append(body, make([]byte, 32)...)
	}
	body = append(body, 0x00)       // session ID len
	body = append(body, 0x00, 0x02) // cipher suites len = 2
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression len=1, null

	var extBytes []byte
	if sni != "" {
		sniName := []byte(sni)
		listLen := 1 + 2 + len(sniName)
		var sniExtData []byte
		sniExtData = binary.BigEndian.AppendUint16(sniExtData, uint16(listLen))
		sniExtData = append(sniExtData, 0x00) // HostName type
		sniExtData = binary.BigEndian.AppendUint16(sniExtData, uint16(len(sniName)))
		sniExtData = append(sniExtData, sniName...)

		extBytes = binary.BigEndian.AppendUint16(extBytes, 0x0000) // server_name type
		extBytes = binary.BigEndian.AppendUint16(extBytes, uint16(len(sniExtData)))
		extBytes = append(extBytes, sniExtData...)
	}

	body = binary.BigEndian.AppendUint16(body, uint16(len(extBytes)))
	body = append(body, extBytes...)

	var res []byte
	res = append(res, 0x01) // ClientHello
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(body)))
	res = append(res, lenBytes[1:]...) // 3-byte length
	res = append(res, body...)
	return res
}

func wrapInCryptoFrame(offset uint64, data []byte) []byte {
	var buf []byte
	buf = quicvarint.Append(buf, 0x06) // Frame type: CRYPTO
	buf = quicvarint.Append(buf, offset)
	buf = quicvarint.Append(buf, uint64(len(data)))
	buf = append(buf, data...)
	return buf
}

// -----------------------------------------------------------------------------
// 1. Bandwidth Parser Unit Tests
// -----------------------------------------------------------------------------

func TestParseBandwidth(t *testing.T) {
	testCases := []struct {
		input       string
		expected    int64
		expectError bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"0", 0, false},
		{"0mb", 0, false},
		{"100b", 100, false},
		{"10k", 10 * 1024, false},
		{"10kb", 10 * 1024, false},
		{"10kib", 10 * 1024, false},
		{"10kb/s", 10 * 1024, false},
		{"10kbps", 10 * 1024, false},
		{"10kb/sec", 10 * 1024, false},
		{"50m", 50 * 1024 * 1024, false},
		{"50mb", 50 * 1024 * 1024, false},
		{"50mib", 50 * 1024 * 1024, false},
		{"1g", 1024 * 1024 * 1024, false},
		{"1gb", 1024 * 1024 * 1024, false},
		{"1gib", 1024 * 1024 * 1024, false},
		{"1.5mb", int64(1.5 * 1024 * 1024), false},
		{" 100 KiB/S ", 100 * 1024, false},
		{"-100kb", 0, false},
		{"invalid", 0, true},
		{"100xyz", 0, true},
		{"1.2.3mb", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			res, err := parseBandwidth(tc.input)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, res)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 2. Token Bucket & Bandwidth Limiter Tests
// -----------------------------------------------------------------------------

func TestPTLSTokenBucket(t *testing.T) {
	t.Run("nil safety", func(t *testing.T) {
		var tb *ptlsTokenBucket
		require.True(t, tb.Allow())
	})

	t.Run("burst and rate consumption", func(t *testing.T) {
		tb := newPTLSTokenBucket(10, 3) // 10 tokens/sec, burst 3

		require.True(t, tb.Allow(), "token 1")
		require.True(t, tb.Allow(), "token 2")
		require.True(t, tb.Allow(), "token 3")
		require.False(t, tb.Allow(), "exhausted tokens")

		time.Sleep(120 * time.Millisecond) // generates ~1.2 tokens
		require.True(t, tb.Allow(), "replenished token")
		require.False(t, tb.Allow(), "exhausted again")
	})

	t.Run("clock drift safety", func(t *testing.T) {
		tb := newPTLSTokenBucket(10, 2)
		tb.lastUpdate = time.Now().Add(10 * time.Minute) // simulate past drift
		require.True(t, tb.Allow())
	})
}

func TestPTLSBandwidthLimiter(t *testing.T) {
	t.Run("nil safety and non-positive rate", func(t *testing.T) {
		require.Nil(t, newPTLSBandwidthLimiter(0))
		require.Nil(t, newPTLSBandwidthLimiter(-100))

		var lim *ptlsBandwidthLimiter
		lim.Wait(100) // should not panic
	})

	t.Run("burst and wait delay", func(t *testing.T) {
		// 100 KB/sec limit
		lim := newPTLSBandwidthLimiter(100 * 1024)
		require.NotNil(t, lim)

		// Consuming 0 or negative bytes does nothing
		lim.Wait(0)
		lim.Wait(-10)

		// First burst within capacity shouldn't cause significant sleep
		start := time.Now()
		lim.Wait(1024)
		require.Less(t, time.Since(start), 20*time.Millisecond)

		// Massive drain causing deficit should sleep proportionally
		lim.tokens = 0
		lim.lastUpdate = time.Now()
		start = time.Now()
		lim.Wait(50 * 1024) // 50 KB at 100 KB/s requires ~500ms
		elapsed := time.Since(start)
		require.GreaterOrEqual(t, elapsed, 400*time.Millisecond)
	})
}

// -----------------------------------------------------------------------------
// 3. UDP Target Resolver Tests
// -----------------------------------------------------------------------------

func TestResolveUDPTarget(t *testing.T) {
	testCases := []struct {
		name        string
		server      string
		port        uint16
		expectedNet string
		expectedAdd string
		expectErr   bool
	}{
		{"empty string", "", 0, "", "", true},
		{"whitespace", "   ", 443, "", "", true},
		{"unix scheme", "unix:/tmp/test.sock", 0, "unixgram", "/tmp/test.sock", false},
		{"unix slash path", "/var/run/fallback.sock", 0, "unixgram", "/var/run/fallback.sock", false},
		{"unix relative dot", "./my.sock", 0, "unixgram", "./my.sock", false},
		{"unix suffix .socket", "app.socket", 0, "unixgram", "app.socket", false},
		{"ip and port", "127.0.0.1", 8443, "udp", "127.0.0.1:8443", false},
		{"ip with embedded port", "127.0.0.1:9000", 0, "udp", "127.0.0.1:9000", false},
		{"domain default port 443", "example.com", 0, "udp", "example.com:443", false},
		{"ipv6 address", "::1", 443, "udp", "[::1]:443", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			network, address, err := resolveUDPTarget(tc.server, tc.port)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedNet, network)
				require.Equal(t, tc.expectedAdd, address)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 4. Initial Packet Parsing & Extraction Tests
// -----------------------------------------------------------------------------

func TestClientHelloParsing(t *testing.T) {
	testRandom := make([]byte, 32)
	for i := range testRandom {
		testRandom[i] = byte(i + 1)
	}
	testSNI := "ptls.target.org"

	t.Run("standard parsing with leading PADDING and PING", func(t *testing.T) {
		ch := buildClientHelloPayload(testRandom, testSNI)
		frame := wrapInCryptoFrame(0, ch)

		var payload []byte
		payload = append(payload, 0x00, 0x00) // PADDING
		payload = append(payload, 0x01)       // PING
		payload = append(payload, frame...)

		random, err := ParseClientHelloRandom(payload)
		require.NoError(t, err)
		require.Equal(t, testRandom, random)

		sni := ParseClientHelloSNI(payload)
		require.Equal(t, testSNI, sni)
	})

	t.Run("client hello without SNI", func(t *testing.T) {
		ch := buildClientHelloPayload(testRandom, "")
		frame := wrapInCryptoFrame(0, ch)

		random, err := ParseClientHelloRandom(frame)
		require.NoError(t, err)
		require.Equal(t, testRandom, random)

		sni := ParseClientHelloSNI(frame)
		require.Empty(t, sni)
	})

	t.Run("empty or truncated frame", func(t *testing.T) {
		_, err := ParseClientHelloRandom(nil)
		require.Error(t, err)

		_, err = ParseClientHelloRandom([]byte{0x06}) // incomplete varint
		require.Error(t, err)

		// CRYPTO frame declaring 100 bytes length with only 5 bytes body
		var badFrame []byte
		badFrame = quicvarint.Append(badFrame, 0x06)
		badFrame = quicvarint.Append(badFrame, 0)
		badFrame = quicvarint.Append(badFrame, 100)
		badFrame = append(badFrame, []byte{1, 2, 3, 4, 5}...)
		_, err = ParseClientHelloRandom(badFrame)
		require.Error(t, err)
	})

	t.Run("unexpected frame before client hello", func(t *testing.T) {
		var payload []byte
		payload = quicvarint.Append(payload, 0x02) // ACK frame (unexpected)
		_, err := ParseClientHelloRandom(payload)
		require.Error(t, err)
	})

	t.Run("crypto frame with non-zero offset", func(t *testing.T) {
		ch := buildClientHelloPayload(testRandom, testSNI)
		frame := wrapInCryptoFrame(100, ch) // non-zero offset
		_, err := ParseClientHelloRandom(frame)
		require.Error(t, err)
	})

	t.Run("short message or non-client-hello type", func(t *testing.T) {
		shortCH := []byte{0x01, 0x00, 0x00, 0x05, 0x03, 0x03} // less than 38 bytes
		frame := wrapInCryptoFrame(0, shortCH)
		_, err := ParseClientHelloRandom(frame)
		require.Error(t, err)

		serverHello := append([]byte{0x02}, make([]byte, 50)...) // type 0x02 = ServerHello
		frame = wrapInCryptoFrame(0, serverHello)
		_, err = ParseClientHelloRandom(frame)
		require.Error(t, err)
	})
}

// -----------------------------------------------------------------------------
// 5. Fallback Relayer Unit & UDP NAT Session Tests
// -----------------------------------------------------------------------------

type mockRawConn struct {
	localAddr       net.Addr
	writePacketFunc func(b []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) (int, error)
}

func (m *mockRawConn) WritePacket(b []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if m.writePacketFunc != nil {
		return m.writePacketFunc(b, addr, oob, gsoSize, ecn)
	}
	return len(b), nil
}
func (m *mockRawConn) ReadPacket() (receivedPacket, error) { return receivedPacket{}, nil }
func (m *mockRawConn) LocalAddr() net.Addr                 { return m.localAddr }
func (m *mockRawConn) SetReadDeadline(time.Time) error     { return nil }
func (m *mockRawConn) Close() error                        { return nil }
func (m *mockRawConn) capabilities() connCapabilities      { return connCapabilities{} }

func TestPTLSFallbackRelayer_Bidirectional(t *testing.T) {
	// 1. Create a dummy UDP target server
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer targetConn.Close()

	targetAddr := targetConn.LocalAddr().(*net.UDPAddr)

	receivedAtTarget := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, rerr := targetConn.ReadFrom(buf)
			if rerr != nil {
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			receivedAtTarget <- msg

			// Echo back with prefix "echo:"
			reply := append([]byte("echo:"), msg...)
			_, _ = targetConn.WriteTo(reply, raddr)
		}
	}()

	// 2. Setup mock serverConn capturing packets sent back to client
	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
	repliedToClient := make(chan []byte, 1)

	mockConn := &mockRawConn{
		localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		writePacketFunc: func(b []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
			if addr.String() == clientAddr.String() {
				msg := make([]byte, len(b))
				copy(msg, b)
				repliedToClient <- msg
			}
			return len(b), nil
		},
	}

	cfg := PTLSFallbackConfig{
		Enabled: true,
		Server:  targetAddr.IP.String(),
		Port:    uint16(targetAddr.Port),
		QPS:     100,
		QoS:     "10mb/s",
		Timeout: 2 * time.Second,
	}

	relayer := newPTLSFallbackRelayer(mockConn, cfg, utils.DefaultLogger)
	require.NotNil(t, relayer)
	defer relayer.Close()

	// 3. Send initial packet to relayer
	initialPacket := []byte("hello-ptls-probe")
	relayer.HandlePacket(initialPacket, clientAddr, packetInfo{})

	// Verify target received initial packet
	select {
	case msg := <-receivedAtTarget:
		require.Equal(t, initialPacket, msg)
	case <-time.After(2 * time.Second):
		t.Fatal("target timed out waiting for relayed packet")
	}

	// Verify client received target's echo
	select {
	case msg := <-repliedToClient:
		require.Equal(t, []byte("echo:hello-ptls-probe"), msg)
	case <-time.After(2 * time.Second):
		t.Fatal("client timed out waiting for echoed response")
	}

	require.True(t, relayer.HasSession(clientAddr))

	// Subsequent packet from same client should use existing session
	secondPacket := []byte("second-data-packet")
	relayer.HandlePacket(secondPacket, clientAddr, packetInfo{})

	select {
	case msg := <-receivedAtTarget:
		require.Equal(t, secondPacket, msg)
	case <-time.After(2 * time.Second):
		t.Fatal("target timed out waiting for second packet")
	}
}

func TestPTLSFallbackRelayer_QPSLimiting(t *testing.T) {
	mockConn := &mockRawConn{localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	cfg := PTLSFallbackConfig{
		Enabled: true,
		Server:  "127.0.0.1",
		Port:    55555,
		QPS:     2, // burst = 4
		Timeout: time.Second,
	}

	relayer := newPTLSFallbackRelayer(mockConn, cfg, utils.DefaultLogger)
	require.NotNil(t, relayer)
	defer relayer.Close()

	// Send from 10 distinct IPs rapidly
	var accepted int
	for i := 1; i <= 10; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i)), Port: 1234}
		relayer.HandlePacket([]byte("probe"), addr, packetInfo{})
		if relayer.HasSession(addr) {
			accepted++
		}
	}

	// Burst was 4, so at most 4 new sessions should have been accepted
	require.LessOrEqual(t, accepted, 5)
	require.GreaterOrEqual(t, accepted, 3)
}

// -----------------------------------------------------------------------------
// 6. CheckPTLS Gatekeeper Integration Tests
// -----------------------------------------------------------------------------

func TestCheckPTLS(t *testing.T) {
	server := &baseServer{logger: utils.DefaultLogger}
	destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	serverTLS, _ := generateTestCertificates(t)
	server.tlsConf = serverTLS

	// Build a valid Initial AEAD sealer to encrypt the test packet
	sealer, _ := handshake.NewInitialAEAD(destConnID, protocol.PerspectiveClient, protocol.Version1)

	random := make([]byte, 32)
	for i := range random {
		random[i] = 0x5a
	}
	clientHello := buildClientHelloPayload(random, "ptls.test.org")
	cryptoFrame := wrapInCryptoFrame(0, clientHello)

	hdr := &wire.Header{
		Type:             protocol.PacketTypeInitial,
		DestConnectionID: destConnID,
		SrcConnectionID:  protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
		Length:           protocol.ByteCount(4 + len(cryptoFrame) + sealer.Overhead()),
		Version:          protocol.Version1,
	}

	extHdr := &wire.ExtendedHeader{
		Header:          *hdr,
		PacketNumber:    1,
		PacketNumberLen: protocol.PacketNumberLen4,
	}

	var rawPacket []byte
	var err error
	rawPacket, err = extHdr.Append(rawPacket, protocol.Version1)
	require.NoError(t, err)

	hdrLen := len(rawPacket)
	rawPacket = sealer.Seal(rawPacket, cryptoFrame, extHdr.PacketNumber, rawPacket[:hdrLen])
	sealer.EncryptHeader(rawPacket[hdrLen:hdrLen+16], &rawPacket[0], rawPacket[hdrLen-4:hdrLen])

	parsedHdr, _, _, err := wire.ParsePacket(rawPacket)
	require.NoError(t, err)

	rPacket := receivedPacket{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111},
		data:       rawPacket,
	}

	t.Run("packet length smaller than header length", func(t *testing.T) {
		shortPacket := receivedPacket{
			remoteAddr: rPacket.remoteAddr,
			data:       rawPacket[:len(rawPacket)-5],
		}
		passed, allowFallback, err := server.checkPTLS(shortPacket, parsedHdr, destConnID, &testServerGatekeeper{})
		require.False(t, passed)
		require.True(t, allowFallback)
		require.Error(t, err)
	})

	t.Run("valid credentials pass gatekeeper", func(t *testing.T) {
		passed, allowFallback, err := server.checkPTLS(rPacket, parsedHdr, destConnID, &customGatekeeper{
			checkSNIFunc: func(sni string) bool { return sni == "ptls.test.org" },
			verifyFunc: func(dcid, r, raw []byte, addr net.Addr) (bool, error) {
				return bytes.Equal(r, random), nil
			},
		})
		require.NoError(t, err)
		require.True(t, passed)
		require.False(t, allowFallback)
	})

	t.Run("invalid credentials trigger fallback", func(t *testing.T) {
		passed, allowFallback, err := server.checkPTLS(rPacket, parsedHdr, destConnID, &customGatekeeper{
			checkSNIFunc: func(sni string) bool { return sni == "ptls.test.org" },
			verifyFunc: func(dcid, r, raw []byte, addr net.Addr) (bool, error) {
				return false, nil // reject verification
			},
		})
		require.NoError(t, err)
		require.False(t, passed)
		require.True(t, allowFallback, "should allow fallback for valid SNI with bad auth")
	})

	t.Run("rejected SNI drops without fallback", func(t *testing.T) {
		passed, allowFallback, err := server.checkPTLS(rPacket, parsedHdr, destConnID, &customGatekeeper{
			checkSNIFunc: func(sni string) bool { return false }, // reject SNI
			verifyFunc: func(dcid, r, raw []byte, addr net.Addr) (bool, error) {
				return true, nil
			},
		})
		require.Error(t, err)
		require.False(t, passed)
		require.False(t, allowFallback, "must NOT allow fallback on rejected SNI")
	})

	t.Run("origDestConnID passed to gatekeeper verify", func(t *testing.T) {
		origID := protocol.ParseConnectionID([]byte{11, 22, 33, 44})
		var capturedDCID []byte
		_, _, _ = server.checkPTLS(rPacket, parsedHdr, origID, &customGatekeeper{
			checkSNIFunc: func(sni string) bool { return true },
			verifyFunc: func(dcid, r, raw []byte, addr net.Addr) (bool, error) {
				capturedDCID = append([]byte(nil), dcid...)
				return true, nil
			},
		})
		require.Equal(t, origID.Bytes(), capturedDCID)
	})
}

type customGatekeeper struct {
	checkSNIFunc func(sni string) bool
	verifyFunc   func(dcid, random, rawPacket []byte, remoteAddr net.Addr) (bool, error)
	fbConfig     PTLSFallbackConfig
}

func (c *customGatekeeper) Read(p []byte) (int, error) { return rand.Read(p) }
func (c *customGatekeeper) VerifyInitial(dcid, r, raw []byte, addr net.Addr) (bool, error) {
	if c.verifyFunc != nil {
		return c.verifyFunc(dcid, r, raw, addr)
	}
	return false, nil
}
func (c *customGatekeeper) GetFallbackConfig() PTLSFallbackConfig { return c.fbConfig }
func (c *customGatekeeper) CheckSNI(sni string) bool {
	if c.checkSNIFunc != nil {
		return c.checkSNIFunc(sni)
	}
	return true
}

// -----------------------------------------------------------------------------
// 7. Full E2E Integration Tests
// -----------------------------------------------------------------------------

func TestPTLS_E2E_FullSuccess(t *testing.T) {
	serverTLS, clientTLS := generateTestCertificates(t)

	var psk [32]byte
	_, _ = rand.Read(psk[:])

	// Attach gatekeeper to server TLS
	serverGK := &testServerGatekeeper{
		pskList: [][32]byte{psk},
	}
	serverTLS.Rand = serverGK

	// Attach DCID consumer to client TLS
	clientRand := newTestClientPTLSRand(psk)
	clientTLS.Rand = clientRand

	listener, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{
		MaxIdleTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server accept worker
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		_, _ = stream.Write(append([]byte("ack:"), buf[:n]...))
		<-conn.Context().Done()
	}()

	// Client dials
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := DialAddr(ctx, serverAddr, clientTLS, &Config{
		MaxIdleTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	defer stream.Close()

	_, err = stream.Write([]byte("ping"))
	require.NoError(t, err)

	reply := make([]byte, 1024)
	n, err := stream.Read(reply)
	require.NoError(t, err)
	require.Equal(t, "ack:ping", string(reply[:n]))

	_ = conn.CloseWithError(0, "")
	<-done
}

func TestPTLS_E2E_MismatchedPSK_Fallback(t *testing.T) {
	serverTLS, clientTLS := generateTestCertificates(t)

	// 1. Setup fallback destination UDP listener
	fbConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer fbConn.Close()

	fbAddr := fbConn.LocalAddr().(*net.UDPAddr)

	var fallbackReceived atomic.Bool
	fbDone := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		_ = fbConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := fbConn.ReadFrom(buf)
		if err == nil && n > 0 {
			fallbackReceived.Store(true)
		}
		close(fbDone)
	}()

	var serverPSK, clientPSK [32]byte
	_, _ = rand.Read(serverPSK[:])
	_, _ = rand.Read(clientPSK[:]) // intentionally mismatched

	serverGK := &testServerGatekeeper{
		pskList: [][32]byte{serverPSK},
		fbConfig: PTLSFallbackConfig{
			Enabled: true,
			Server:  fbAddr.IP.String(),
			Port:    uint16(fbAddr.Port),
			QPS:     50,
			Timeout: 2 * time.Second,
		},
	}
	serverTLS.Rand = serverGK
	clientTLS.Rand = newTestClientPTLSRand(clientPSK)

	listener, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{
		MaxIdleTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Client attempts to dial with wrong PSK; should fail / time out
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = DialAddr(ctx, serverAddr, clientTLS, &Config{
		MaxIdleTimeout: 1 * time.Second,
	})
	require.Error(t, err, "client should fail to establish QUIC connection")

	<-fbDone
	require.True(t, fallbackReceived.Load(), "fallback backend should have received the unauthenticated Initial packet")
}

func TestPTLS_E2E_SNIRejected_SilentDrop(t *testing.T) {
	serverTLS, clientTLS := generateTestCertificates(t)

	fbConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer fbConn.Close()

	fbAddr := fbConn.LocalAddr().(*net.UDPAddr)

	var fbPktCount atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = fbConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := fbConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				fbPktCount.Add(1)
			}
		}
	}()

	var psk [32]byte
	_, _ = rand.Read(psk[:])

	serverGK := &testServerGatekeeper{
		pskList: [][32]byte{psk},
		fbConfig: PTLSFallbackConfig{
			Enabled: true,
			Server:  fbAddr.IP.String(),
			Port:    uint16(fbAddr.Port),
		},
		allowSNI: func(sni string) bool {
			return false // reject all SNI
		},
	}
	serverTLS.Rand = serverGK
	clientTLS.Rand = newTestClientPTLSRand(psk)
	clientTLS.ServerName = "rejected.sni.com"

	listener, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{
		MaxIdleTimeout: time.Second,
	})
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = DialAddr(ctx, listener.Addr().String(), clientTLS, &Config{
		MaxIdleTimeout: 500 * time.Millisecond,
	})
	require.Error(t, err)

	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(0), fbPktCount.Load(), "rejected SNI must not be forwarded to fallback")
}
