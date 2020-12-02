package socks5

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/require"
)

func TestSock_Request(t *testing.T) {
	input, err := hex.DecodeString("050100018c52760401bb")
	require.NoError(t, err)
	inputRead := bytes.NewReader(input)
	cm := &connMock{}
	readM := cm.On("Read", mock.Anything)
	readM.Run(func(args mock.Arguments) {
		n, err := inputRead.Read(args[0].([]byte))
		readM.ReturnArguments = mock.Arguments{n, err}
	})

	writeInput, err := hex.DecodeString("05000001c0a8011bde8c")

	cm.On("Write", writeInput).Return(len(writeInput), nil)
	s := Sock{
		con: cm,
		dialer: func(network, address string) (conn Conn, e error) {
			rc := &connMock{}
			nam := &netAddrMock{}
			nam.On("String").Return("192.168.1.27:56972")
			rc.On("LocalAddr").Return(nam)
			return rc, nil
		},
	}
	require.NoError(t, s.Request())
}

type connMock struct {
	mock.Mock
}

func (cm *connMock) Read(b []byte) (n int, err error) {
	called := cm.Called(b)
	return called.Int(0), called.Error(1)
}

func (cm *connMock) Write(b []byte) (n int, err error) {
	called := cm.Called(b)
	return called.Int(0), called.Error(1)
}

func (cm *connMock) Close() error {
	return cm.Called().Error(0)
}

func (cm *connMock) LocalAddr() net.Addr {
	return cm.Called().Get(0).(net.Addr)
}

type netAddrMock struct {
	mock.Mock
}

func (nam *netAddrMock) Network() string {
	return nam.Called().String(0)
}

func (nam *netAddrMock) String() string {
	return nam.Called().String(0)
}
