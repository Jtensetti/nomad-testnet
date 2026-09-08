package rlnc

// GF(2^8) arithmetic using the AES irreducible polynomial x^8+x^4+x^3+x+1.
func add(a, b byte) byte { return a ^ b }

func mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func pow(a byte, n int) byte {
	var r byte = 1
	for n > 0 {
		if n&1 == 1 {
			r = mul(r, a)
		}
		a = mul(a, a)
		n >>= 1
	}
	return r
}

func inv(a byte) byte {
	if a == 0 {
		panic("inverse of zero")
	}
	return pow(a, 254)
}
