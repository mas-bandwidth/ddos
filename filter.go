package filter

import (
	"bytes"
	"hash/fnv"
	"encoding/binary"
)

func GeneratePittle(output []byte, fromAddress []byte, toAddress []byte, packetLength int) {

	var packetLengthData [2]byte
	binary.LittleEndian.PutUint16(packetLengthData[:], uint16(packetLength))

	sum := uint16(0)

	for i := 0; i < len(fromAddress); i++ {
		sum += uint16(fromAddress[i])
	}

	for i := 0; i < len(toAddress); i++ {
		sum += uint16(toAddress[i])
	}

	sum += uint16(packetLengthData[0])
	sum += uint16(packetLengthData[1])

	var sumData [2]byte
	binary.LittleEndian.PutUint16(sumData[:], sum)

	output[0] = 1 | (sumData[0] ^ sumData[1] ^ 193)
	output[1] = 1 | ((255 - output[0]) ^ 113)
}

func GenerateChonkle(output []byte, magic []byte, fromAddressData []byte, toAddressData []byte, packetLength int) {

	var packetLengthData [2]byte
	binary.LittleEndian.PutUint16(packetLengthData[:], uint16(packetLength))

	hash := fnv.New64a()
	hash.Write(magic)
	hash.Write(fromAddressData)
	hash.Write(toAddressData)
	hash.Write(packetLengthData[:])
	hashValue := hash.Sum64()

	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], uint64(hashValue))

	output[0] = ((data[6] & 0xC0) >> 6) + 42
	output[1] = (data[3] & 0x1F) + 200
	output[2] = ((data[2] & 0xFC) >> 2) + 5
	output[3] = data[0]
	output[4] = (data[2] & 0x03) + 78
	output[5] = (data[4] & 0x7F) + 96
	output[6] = ((data[1] & 0xFC) >> 2) + 100
	if (data[7] & 1) == 0 {
		output[7] = 79
	} else {
		output[7] = 7
	}
	if (data[4] & 0x80) == 0 {
		output[8] = 37
	} else {
		output[8] = 83
	}
	output[9] = (data[5] & 0x07) + 124
	output[10] = ((data[1] & 0xE0) >> 5) + 175
	output[11] = (data[6] & 0x3F) + 33
	value := (data[1] & 0x03)
	if value == 0 {
		output[12] = 97
	} else if value == 1 {
		output[12] = 5
	} else if value == 2 {
		output[12] = 43
	} else {
		output[12] = 13
	}
	output[13] = ((data[5] & 0xF8) >> 3) + 210
	output[14] = ((data[7] & 0xFE) >> 1) + 17
}

func BasicPacketFilter(data []byte, packetLength int) bool {

	if packetLength < 18 {
		return false
	}

	if data[0] < 0x32 || data[0] > 0x3C {
		return false
	}

	if data[2] != (1 | ((255 - data[1]) ^ 113)) {
		return false
	}

	if data[3] < 0x2A || data[3] > 0x2D {
		return false
	}

	if data[4] < 0xC8 || data[4] > 0xE7 {
		return false
	}

	if data[5] < 0x05 || data[5] > 0x44 {
		return false
	}

	if data[7] < 0x4E || data[7] > 0x51 {
		return false
	}

	if data[8] < 0x60 || data[8] > 0xDF {
		return false
	}

	if data[9] < 0x64 || data[9] > 0xE3 {
		return false
	}

	if data[10] != 0x07 && data[10] != 0x4F {
		return false
	}

	if data[11] != 0x25 && data[11] != 0x53 {
		return false
	}

	if data[12] < 0x7C || data[12] > 0x83 {
		return false
	}

	if data[13] < 0xAF || data[13] > 0xB6 {
		return false
	}

	if data[14] < 0x21 || data[14] > 0x60 {
		return false
	}

	if data[15] != 0x61 && data[15] != 0x05 && data[15] != 0x2B && data[15] != 0x0D {
		return false
	}

	if data[16] < 0xD2 || data[16] > 0xF1 {
		return false
	}

	if data[17] < 0x11 || data[17] > 0x90 {
		return false
	}

	return true
}

func AdvancedPacketFilter(data []byte, magic []byte, fromAddress []byte, toAddress []byte, packetLength int) bool {
	if packetLength < 18 {
		return false
	}
	var a [2]byte
	var b [15]byte
	GeneratePittle(a[:], fromAddress, toAddress, packetLength)
	GenerateChonkle(b[:], magic, fromAddress, toAddress, packetLength)
	if bytes.Compare(a[:], data[1:3]) != 0 {
		return false
	}
	if bytes.Compare(b[:], data[3:18]) != 0 {
		return false
	}
	return true
}
