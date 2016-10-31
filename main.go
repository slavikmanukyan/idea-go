package main

import "fmt"

func gcd(a int, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func xgcd(a int, b int) (int, int, int) {
	prevx, x := 1, 0
	prevy, y := 0, 1
	for b != 0 {
		q := a / b
		x, prevx = prevx-q*x, x
		y, prevy = prevy-q*y, y
		a, b = b, a%b
	}
	return a, prevx, prevy
}

func mul(a int16, b int16) int16 {
	r := int32(a * b)
	if r != 0 {
		return int16((r % 0x10001) & 0xFFFF)
	}
	return int16(int32(1-a-b) & 0xFFFF)
}

// IDEAEncryptionKeySchedule Encryption Key Schedule function for IDEA algorithm
func IDEAEncryptionKeySchedule(key [16]uint8) [52]uint16 {
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

// func IDEAInvertEncryptionKey(key [52]uint16) [52]uint16 {
//    invKey = new int[key.length]
//    int p = 0
//    int i = rounds * 6
//    invKey[i + 0] = mulInv(key[p++])
//    invKey[i + 1] = addInv(key[p++])
//    invKey[i + 2] = addInv(key[p++])
//    invKey[i + 3] = mulInv(key[p++])
//    for  r := rounds - 1; r >= 0; r-- {
//       i = r * 6
//       int m = r > 0 ? 2 : 1
//       int n = r > 0 ? 1 : 2
//       invKey[i + 4] =        key[p++]
//       invKey[i + 5] =        key[p++]
//       invKey[i + 0] = mulInv(key[p++])
//       invKey[i + m] = addInv(key[p++])
//       invKey[i + n] = addInv(key[p++])
//       invKey[i + 3] = mulInv(key[p++])
//     }
//    return invKey
// }

func main() {
	// fmt.Println(IDEAEncryptionKeySchedule([16]uint8{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08}))
	fmt.Println(mul(800, 0))
}
