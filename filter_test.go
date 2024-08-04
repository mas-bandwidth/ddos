package filter

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func randomBytes(buffer []byte) {
	for i := 0; i < len(buffer); i++ {
		buffer[i] = byte(rand.Intn(256))
	}
}

func TestPittleAndChonkle(t *testing.T) {
	rand.Seed(42)
	var output [1024]byte
	output[0] = 0x32
	iterations := 1000
	for i := 0; i < iterations; i++ {
		var magic [8]byte
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(magic[:])
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		packetLength := 18 + (i % (len(output) - 18))
		GeneratePittle(output[1:3], fromAddress[:], toAddress[:], packetLength)
		GenerateChonkle(output[3:18], magic[:], fromAddress[:], toAddress[:], packetLength)
		assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
		assert.Equal(t, true, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], toAddress[:], packetLength))
	}
}

func TestBasicPacketFilter(t *testing.T) {
	rand.Seed(42)
	var output [256]byte
	pass := 0
	iterations := 10000
	for i := 0; i < iterations; i++ {
		randomBytes(output[:])
		packetLength := i % len(output)
		assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
	}
	assert.Equal(t, 0, pass)
}

func TestAdvancedBasicPacketFilter(t *testing.T) {
	rand.Seed(42)
	var output [1000]byte
	iterations := 10000
	for i := 0; i < iterations; i++ {
		var magic [8]byte
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(magic[:])
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		randomBytes(output[:])
		packetLength := i % len(output)
		assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
		assert.Equal(t, false, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], toAddress[:], packetLength))
	}
}
