package bb4

import (
	"crypto/rand"
	"errors"
	"io"
	"encoding/base64"
	"encoding/binary"
)

const (
	KeyLength = 32
	NonceLength = 16
	FixedLength = 16
	XorBlockLength = 64
	AEADBlockLength = 48

	keyLength64   = 4
	nonceLength64 = 2
	fixedLength64 = 2
	stateLength64 = 8
	macLength64 = 2

	round         = 32
	maxTime	= 0xFFFFFFFFFFFFFFFF
)

type Cipher struct {
	Key    [keyLength64]uint64
	Nonce  [nonceLength64]uint64
	mstate [stateLength64]uint64
	nstate [stateLength64]uint64
	times  uint64
	macState [macLength64]uint64
}

func NewCipher(key, nonce []byte) (cipher *Cipher, err error) {
	cipher = new(Cipher)
	if len(key) != KeyLength {
		return nil, errors.New("key length is incorrect")
	}

	for i := 0; i < keyLength64; i += 1  {
		cipher.Key[i] = bytesToInt64(key[8*i : 8*i+8])
	}
	if len(nonce) != NonceLength {
		return nil, errors.New("nonce length is incorrect")
	}
	for i := 0; i < nonceLength64; i +=1{
		cipher.Nonce[i] = bytesToInt64(nonce[8*i:8*i+8])
	}
	return cipher, nil
}

func (cipher *Cipher) Reset() {
	cipher.times = 0
}

func (cipher *Cipher) XORKeyStream(dst, src []byte) {
	idx := 0
	nxt := 0
	ls := len(src)

	nxt= min(idx+XorBlockLength, ls)
	for idx < ls {
		c := cipher.prf()
		var cbytes [XorBlockLength]byte
		for j:=0; j< stateLength64; j++ {
			buf := int64ToBytes(c[j])
			copy(cbytes[8*j: 8*j+8], buf)
		}

		for j:=0; j<XorBlockLength; j++ {
			if idx + j >= nxt {
				break
			}
			dst[idx+j] = cbytes[j] ^ src[idx+j]
		}
		idx = nxt
		nxt = min(idx+XorBlockLength, ls)
	}
}

// initial state: 0xF0F1F2F3F4F5F6F7, key0, key1, key2, nonce0, times, key3, nonce1
func (cipher *Cipher) ikf() {
	cipher.mstate[0] = 0xF0F1F2F3F4F5F6F7
	cipher.mstate[1] = cipher.Key[0]
	cipher.mstate[2] = cipher.Key[1]
	cipher.mstate[3] = cipher.Key[2]
	cipher.mstate[4] = cipher.Nonce[0]
	cipher.mstate[5] = cipher.times
	cipher.mstate[6] = cipher.Key[3]
	cipher.mstate[7] = cipher.Nonce[1]
}

// [6, 5, 2, 4, 0, 7, 3, 1] xor
// [2, 4, 7, 0, 5, 1, 6, 3] >> (31, 59, 37, 22, 07, 08, 23, 46) + 
// [7, 6, 2, 5, 3, 4, 1, 0] ->
// In even round: [1, 2, 3, 7, 5, 4, 0, 6]
// In odd round: [4, 3, 2, 5, 6, 1, 0, 7]

// In even round:
// [1, 3, 0, 2, 5, 7, 4, 6] +
// [2, 0, 3, 1, 6, 4, 7, 5] >> (31, 37, 07, 24, 31, 37, 07, 24) xor
// [3, 0, 1, 2, 7, 4, 5, 6] -> 
// [1, 2, 3, 7, 5, 4, 0, 6]
// In odd round: 
// [0, 1, 3, 2, 4, 5, 7, 6] +
// [2, 0, 1, 3, 6, 4, 5, 7] >> (59, 22, 08, 46, 59, 22, 08, 46) xor
// [0, 2, 3, 1, 4, 6, 7, 5] ->
// [4, 3, 2, 5, 6, 1, 0, 7]
func (cipher *Cipher) prf() []uint64 {
	cipher.ikf()
	for i := 0; i < round; i++ {
		if i%2 == 0 {
			cipher.nstate[1] = ((cipher.mstate[1] ^ cipher.mstate[2]) >> 33 | (cipher.mstate[1] ^ cipher.mstate[2]) << 31) + cipher.mstate[3]
			cipher.nstate[2] = ((cipher.mstate[3] ^ cipher.mstate[0]) >> 27 | (cipher.mstate[3] ^ cipher.mstate[0]) << 37) + cipher.mstate[0]
			cipher.nstate[3] = ((cipher.mstate[0] ^ cipher.mstate[3]) >> 57 | (cipher.mstate[0] ^ cipher.mstate[3]) <<  7) + cipher.mstate[1]
			cipher.nstate[7] = ((cipher.mstate[2] ^ cipher.mstate[1]) >> 40 | (cipher.mstate[2] ^ cipher.mstate[1]) << 24) + cipher.mstate[2]
			cipher.nstate[5] = ((cipher.mstate[5] ^ cipher.mstate[6]) >> 33 | (cipher.mstate[5] ^ cipher.mstate[6]) << 31) + cipher.mstate[7]
			cipher.nstate[4] = ((cipher.mstate[7] ^ cipher.mstate[4]) >> 27 | (cipher.mstate[7] ^ cipher.mstate[4]) << 37) + cipher.mstate[4]
			cipher.nstate[0] = ((cipher.mstate[4] ^ cipher.mstate[7]) >> 57 | (cipher.mstate[4] ^ cipher.mstate[7]) << 07) + cipher.mstate[5]
			cipher.nstate[6] = ((cipher.mstate[6] ^ cipher.mstate[5]) >> 40 | (cipher.mstate[6] ^ cipher.mstate[5]) << 24) + cipher.mstate[6]
		} else {
			cipher.nstate[4] = ((cipher.mstate[0] ^ cipher.mstate[2]) >>  5 | (cipher.mstate[0] ^ cipher.mstate[2]) << 59) + cipher.mstate[0]
			cipher.nstate[3] = ((cipher.mstate[1] ^ cipher.mstate[0]) >> 42 | (cipher.mstate[1] ^ cipher.mstate[0]) << 22) + cipher.mstate[2]
			cipher.nstate[2] = ((cipher.mstate[3] ^ cipher.mstate[1]) >> 56 | (cipher.mstate[3] ^ cipher.mstate[1]) <<  8) + cipher.mstate[3]
			cipher.nstate[5] = ((cipher.mstate[2] ^ cipher.mstate[3]) >> 18 | (cipher.mstate[2] ^ cipher.mstate[3]) << 46) + cipher.mstate[1]
			cipher.nstate[6] = ((cipher.mstate[4] ^ cipher.mstate[6]) >>  5 | (cipher.mstate[4] ^ cipher.mstate[6]) << 59) + cipher.mstate[4]
			cipher.nstate[1] = ((cipher.mstate[5] ^ cipher.mstate[4]) >> 42 | (cipher.mstate[5] ^ cipher.mstate[4]) << 22) + cipher.mstate[6]
			cipher.nstate[0] = ((cipher.mstate[7] ^ cipher.mstate[5]) >> 56 | (cipher.mstate[7] ^ cipher.mstate[5]) <<  8) + cipher.mstate[7]
			cipher.nstate[7] = ((cipher.mstate[6] ^ cipher.mstate[7]) >> 18 | (cipher.mstate[6] ^ cipher.mstate[7]) << 46) + cipher.mstate[5]
		}
		copy(cipher.mstate[:], cipher.nstate[:])
	}
	cipher.times += 1

	var buf [stateLength64]uint64
	copy(buf[:], cipher.mstate[:])
	return buf[:]
}

func GenKey() (key []byte, err error){
	key = make([]byte, KeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenNonce() (nonce []byte, err error){
	nonce = make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func int64ToBytes(n uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}

func bytesToInt64(buf []byte) uint64 {
	return uint64(binary.BigEndian.Uint64(buf))
}

func bytesToBase64(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

func base64ToBytes(str string) (buf []byte, err error) {
	return base64.StdEncoding.DecodeString(str)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
