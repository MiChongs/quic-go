package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type mockPTLSDCIDConsumer struct {
	dcid  []byte
	calls int
}

func (m *mockPTLSDCIDConsumer) SetDestinationConnectionID(dcid []byte) {
	m.dcid = append([]byte(nil), dcid...)
	m.calls++
}

func (m *mockPTLSDCIDConsumer) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

func getTestClientTLSConfig() *tls.Config {
	return &tls.Config{
		ServerName: "localhost",
		NextProtos: []string{"h3"},
	}
}

func TestCryptoSetupClient_PTLSDCIDInjection_Standard(t *testing.T) {
	consumer := &mockPTLSDCIDConsumer{}
	tlsConf := getTestClientTLSConfig()
	tlsConf.Rand = consumer

	connID := protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	tp := &wire.TransportParameters{}
	rttStats := utils.NewRTTStats()

	cs, err := NewCryptoSetupClient(
		connID,
		tp,
		tlsConf,
		false,
		false,
		rttStats,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.NoError(t, err)
	require.NotNil(t, cs)

	require.Equal(t, 1, consumer.calls)
	require.True(t, bytes.Equal(connID.Bytes(), consumer.dcid), "DCID was not correctly passed to consumer")
}

func TestCryptoSetupClient_PTLSDCIDInjection_Lengths(t *testing.T) {
	testCases := []struct {
		name   string
		connID protocol.ConnectionID
	}{
		{
			name:   "empty DCID (0 bytes)",
			connID: protocol.ConnectionID{},
		},
		{
			name:   "single byte DCID",
			connID: protocol.ParseConnectionID([]byte{0x42}),
		},
		{
			name:   "16 bytes DCID",
			connID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
		},
		{
			name:   "max 20 bytes DCID",
			connID: protocol.ParseConnectionID(bytes.Repeat([]byte{0xaa}, protocol.MaxConnIDLen)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			consumer := &mockPTLSDCIDConsumer{}
			tlsConf := getTestClientTLSConfig()
			tlsConf.Rand = consumer

			cs, err := NewCryptoSetupClient(
				tc.connID,
				&wire.TransportParameters{},
				tlsConf,
				false,
				false,
				utils.NewRTTStats(),
				nil,
				utils.DefaultLogger,
				protocol.Version1,
			)
			require.NoError(t, err)
			require.NotNil(t, cs)

			require.Equal(t, 1, consumer.calls)
			require.True(t, bytes.Equal(tc.connID.Bytes(), consumer.dcid))
		})
	}
}

func TestCryptoSetupClient_PTLSDCIDInjection_NilOrNonPTLSRand(t *testing.T) {
	t.Run("nil Rand in tls.Config", func(t *testing.T) {
		tlsConf := getTestClientTLSConfig()
		tlsConf.Rand = nil

		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		cs, err := NewCryptoSetupClient(
			connID,
			&wire.TransportParameters{},
			tlsConf,
			false,
			false,
			utils.NewRTTStats(),
			nil,
			utils.DefaultLogger,
			protocol.Version1,
		)
		require.NoError(t, err)
		require.NotNil(t, cs)
	})

	t.Run("standard non-PTLS rand.Reader", func(t *testing.T) {
		tlsConf := getTestClientTLSConfig()
		tlsConf.Rand = rand.Reader

		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		cs, err := NewCryptoSetupClient(
			connID,
			&wire.TransportParameters{},
			tlsConf,
			false,
			false,
			utils.NewRTTStats(),
			nil,
			utils.DefaultLogger,
			protocol.Version1,
		)
		require.NoError(t, err)
		require.NotNil(t, cs)
	})
}

func TestCryptoSetupClient_PTLSDCIDInjection_MultipleInstances(t *testing.T) {
	consumer := &mockPTLSDCIDConsumer{}
	tlsConf := getTestClientTLSConfig()
	tlsConf.Rand = consumer

	id1 := protocol.ParseConnectionID([]byte{0xaa, 0xbb})
	id2 := protocol.ParseConnectionID([]byte{0xcc, 0xdd})

	_, err := NewCryptoSetupClient(
		id1,
		&wire.TransportParameters{},
		tlsConf,
		false,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.NoError(t, err)
	require.Equal(t, 1, consumer.calls)
	require.Equal(t, id1.Bytes(), consumer.dcid)

	_, err = NewCryptoSetupClient(
		id2,
		&wire.TransportParameters{},
		tlsConf,
		false,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.NoError(t, err)
	require.Equal(t, 2, consumer.calls)
	require.Equal(t, id2.Bytes(), consumer.dcid)
}
