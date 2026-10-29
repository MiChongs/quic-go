package quic

import (
	"errors"
	"net"
	"time"

	"github.com/sagernet/quic-go/quicvarint"
)

// PTLSDCIDConsumer is implemented by tls.Config.Rand on the client side.
// quic-go invokes SetDestinationConnectionID before generating the Initial packet
// so the client can bind ClientHello.random to the initial DCID.
type PTLSDCIDConsumer interface {
	SetDestinationConnectionID(dcid []byte)
}

// PTLSFallbackConfig holds the configuration required by quic-go's transport-level UDP fallback engine.
type PTLSFallbackConfig struct {
	Enabled bool
	Server  string
	Port    uint16
	QPS     int
	QoS     string
	Timeout time.Duration
}

// PTLSInitialGatekeeper is implemented by tls.Config.Rand on the server side.
// It provides stateless cryptographic verification and declarative policy parameters
// for quic-go to enforce at the transport layer.
type PTLSInitialGatekeeper interface {
	// VerifyInitial verifies the unpacked ClientHello.random using pre-shared keys.
	VerifyInitial(dcid []byte, clientHelloRandom []byte, rawPacket []byte, remoteAddr net.Addr) (passed bool, err error)

	// GetFallbackConfig returns the fallback proxy configuration.
	GetFallbackConfig() PTLSFallbackConfig
}

// PTLSSNIChecker may optionally be implemented by a PTLSInitialGatekeeper.
// When CheckSNI rejects the ClientHello server name, the Initial packet is
// dropped without being relayed to the fallback target.
type PTLSSNIChecker interface {
	CheckSNI(serverName string) bool
}

// ParseClientHelloRandom extracts the 32-byte ClientHello.random from the decrypted Initial packet payload.
func ParseClientHelloRandom(payload []byte) ([]byte, error) {
	cryptoData, err := findClientHelloCryptoData(payload)
	if err != nil {
		return nil, err
	}
	if len(cryptoData) < 38 {
		return nil, errors.New("ptls: client hello data too short")
	}
	if cryptoData[0] != 0x01 {
		return nil, errors.New("ptls: handshake message is not client hello")
	}
	random := make([]byte, 32)
	copy(random, cryptoData[6:38])
	return random, nil
}

func findClientHelloCryptoData(payload []byte) ([]byte, error) {
	for len(payload) > 0 {
		if payload[0] == 0x00 { // PADDING
			payload = payload[1:]
			continue
		}
		typeID, n, err := quicvarint.Parse(payload)
		if err != nil {
			return nil, err
		}
		payload = payload[n:]

		switch typeID {
		case 0x01: // PING
			continue
		case 0x06: // CRYPTO
			offset, n, err := quicvarint.Parse(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			length, n, err := quicvarint.Parse(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			if uint64(len(payload)) < length {
				return nil, errors.New("ptls: truncated crypto frame")
			}
			cryptoData := payload[:length]
			if offset == 0 {
				return cryptoData, nil
			}
			payload = payload[length:]
		default:
			return nil, errors.New("ptls: unexpected frame before client hello")
		}
	}
	return nil, errors.New("ptls: client hello not found in initial packet")
}

// ParseClientHelloSNI extracts the server_name extension from the ClientHello carried in the
// decrypted Initial packet payload. It returns an empty string if the ClientHello has no SNI or
// cannot be parsed.
func ParseClientHelloSNI(payload []byte) string {
	cryptoData, err := findClientHelloCryptoData(payload)
	if err != nil || len(cryptoData) < 4 || cryptoData[0] != 0x01 {
		return ""
	}
	msgLen := int(cryptoData[1])<<16 | int(cryptoData[2])<<8 | int(cryptoData[3])
	body := cryptoData[4:]
	if len(body) > msgLen {
		body = body[:msgLen]
	}
	// legacy_version(2) + random(32)
	if len(body) < 34 {
		return ""
	}
	body = body[34:]
	// legacy_session_id
	body, ok := skipVector(body, 1)
	if !ok {
		return ""
	}
	// cipher_suites
	if body, ok = skipVector(body, 2); !ok {
		return ""
	}
	// legacy_compression_methods
	if body, ok = skipVector(body, 1); !ok {
		return ""
	}
	if len(body) < 2 {
		return ""
	}
	extLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if len(body) < extLen {
		return ""
	}
	extensions := body[:extLen]
	for len(extensions) >= 4 {
		extType := uint16(extensions[0])<<8 | uint16(extensions[1])
		length := int(extensions[2])<<8 | int(extensions[3])
		extensions = extensions[4:]
		if len(extensions) < length {
			return ""
		}
		data := extensions[:length]
		extensions = extensions[length:]
		if extType != 0x0000 { // server_name
			continue
		}
		if len(data) < 2 {
			return ""
		}
		listLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if len(data) < listLen {
			return ""
		}
		data = data[:listLen]
		for len(data) >= 3 {
			nameType := data[0]
			nameLen := int(data[1])<<8 | int(data[2])
			data = data[3:]
			if len(data) < nameLen {
				return ""
			}
			if nameType == 0x00 { // host_name
				return string(data[:nameLen])
			}
			data = data[nameLen:]
		}
		return ""
	}
	return ""
}

func skipVector(b []byte, lengthBytes int) ([]byte, bool) {
	if len(b) < lengthBytes {
		return nil, false
	}
	var length int
	for i := 0; i < lengthBytes; i++ {
		length = length<<8 | int(b[i])
	}
	b = b[lengthBytes:]
	if len(b) < length {
		return nil, false
	}
	return b[length:], true
}
