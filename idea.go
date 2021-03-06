package idea

const BlockSize int = 8
const KeySize int = 16

// Block for encrypting decripting
type Block struct {
	key           [16]uint8
	encryptionKey [52]uint16
	decryptionKey [52]uint16
}

type cryptoBlock interface {
	Crypt([]uint8) []uint8
	Decrypt([]uint8) []uint8
}

func (b *Block) SetKey(key []uint8) {
	for i := 0; i < KeySize; i++ {
		b.key[i] = key[i]
	}
	b.encryptionKey = EncryptionKeySchedule(b.key)
	b.decryptionKey = InvertEncryptionKey(b.encryptionKey)
}

func (b *Block) GenerateKeys() {
	b.encryptionKey = EncryptionKeySchedule(b.key)
	b.decryptionKey = InvertEncryptionKey(b.encryptionKey)
}

func (b Block) Crypt(data []uint8) []uint8 {
	dataArray := [8]uint8{}
	copy(dataArray[:], data[0:8])
	res := crypt(dataArray, b.encryptionKey)
	return res[0:8]
}

func (b Block) Decrypt(data []uint8) []uint8 {
	dataArray := [8]uint8{}
	copy(dataArray[:], data[0:8])
	res := crypt(dataArray, b.decryptionKey)
	return res[0:8]
}

func mul(a uint16, b uint16) uint16 {
	r := int32(a) * int32(b)
	if r != 0 {
		rh := (r >> 16) & 0xFFFF
		rl := r & 0xFFFF
		if rl > rh {
			return uint16(rl - rh)
		}
		return uint16((rl - rh + 0x10001) & 0xFFFF)
	}
	return uint16(int32(1-a-b) & 0xFFFF)
}

func add(a uint16, b uint16) uint16 {
	return uint16(int32(a+b) & 0xFFFF)
}

func addInv(x uint16) uint16 {
	return uint16(int32(0x10000-int32(x)) & 0xFFFF)
}

func mulInv(x uint16) uint16 {
	if x <= 1 {
		return x
	}
	y := 0x10001
	t0 := 1
	t1 := 0
	for {
		t1 += y / int(x) * t0
		y = y % int(x)
		if y == 1 {
			return uint16(0x10001 - t1)
		}
		t0 += int(x) / y * t1
		x %= uint16(y)
		if x == 1 {
			return uint16(t0)
		}
	}
}

func crypt(data [8]uint8, subKey [52]uint16) [8]uint8 {
	x0 := (uint16(data[0]&0xFF) << 8) | uint16(data[1]&0xFF)
	x1 := (uint16(data[2]&0xFF) << 8) | uint16(data[3]&0xFF)
	x2 := (uint16(data[4]&0xFF) << 8) | uint16(data[5]&0xFF)
	x3 := (uint16(data[6]&0xFF) << 8) | uint16(data[7]&0xFF)
	p := 0
	for round := 0; round < 8; round++ {
		y0 := mul(x0, subKey[p])
		p++
		y1 := add(x1, subKey[p])
		p++
		y2 := add(x2, subKey[p])
		p++
		y3 := mul(x3, subKey[p])
		p++

		t0 := mul(y0^y2, subKey[p])
		p++
		t1 := add(y1^y3, t0)
		t2 := mul(t1, subKey[p])
		p++
		t3 := add(t0, t2)

		x0 = y0 ^ t2
		x1 = y2 ^ t2
		x2 = y1 ^ t3
		x3 = y3 ^ t3
	}
	r0 := mul(x0, subKey[p])
	p++
	r1 := add(x2, subKey[p])
	p++
	r2 := add(x1, subKey[p])
	p++
	r3 := mul(x3, subKey[p])

	result := [8]uint8{}
	result[0] = uint8(r0 >> 8)
	result[1] = uint8(r0)
	result[2] = uint8(r1 >> 8)
	result[3] = uint8(r1)
	result[4] = uint8(r2 >> 8)
	result[5] = uint8(r2)
	result[6] = uint8(r3 >> 8)
	result[7] = uint8(r3)

	return result
}

func EncryptionKeySchedule(key [16]uint8) [52]uint16 {
	subkeys := [52]uint16{}
	for i := 0; i < 8; i++ {
		subkeys[i] = ((uint16(key[2*i]) & 0xFF) << 8) | uint16(key[2*i+1]&0xFF)
	}
	for i := 8; i < 52; i++ {
		var a, b int
		if (i+1)%8 != 0 {
			a = i - 7
		} else {
			a = i - 15
		}
		if (i+2)%8 < 2 {
			b = i - 14
		} else {
			b = i - 6
		}
		subkeys[i] = ((uint16(subkeys[a]) << 9) | uint16(subkeys[b]>>7)) & 0xFFFF
	}
	return subkeys
}

func InvertEncryptionKey(key [52]uint16) [52]uint16 {
	invKey := [52]uint16{}
	p := 0
	i := 8 * 6
	invKey[i+0] = mulInv(key[p])
	p++
	invKey[i+1] = addInv(key[p])
	p++
	invKey[i+2] = addInv(key[p])
	p++
	invKey[i+3] = mulInv(key[p])
	p++
	for r := 7; r >= 0; r-- {
		i = r * 6
		var (
			n int
			m int
		)
		if r > 0 {
			n = 1
			m = 2
		} else {
			n = 2
			m = 1
		}

		invKey[i+4] = key[p]
		p++
		invKey[i+5] = key[p]
		p++
		invKey[i+0] = mulInv(key[p])
		p++
		invKey[i+m] = addInv(key[p])
		p++
		invKey[i+n] = addInv(key[p])
		p++
		invKey[i+3] = mulInv(key[p])
		p++
	}
	return invKey
}

func NewBlock(key []uint8) cryptoBlock {
	b := Block{}
	b.SetKey(key)
	return b
}
