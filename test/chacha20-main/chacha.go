package main

import (
	"bb4"
	"crypto/rand"
	"flag"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/chacha20"
)

var (
	inputFile  string
	outputFile string
	keyFile    string
	nonceFile  string
	length     int

	genKey   bool
	genNonce bool
	xorMode  bool
	encMode  bool
	decMode  bool
	testMode bool
)

func init() {
	flag.BoolVar(&genKey, "genkey", false, "-genkey -output key.txt")
	flag.BoolVar(&genNonce, "gennonce", false, "-gennonce -output nonce.txt")
	flag.BoolVar(&xorMode, "xor", false, "-xor -key key.txt [-nonce nonce.txt] [-input message.txt/-length 512] -output encrypted.txt")
	flag.BoolVar(&encMode, "enc", false, "-enc -key key.txt [-nonce nonce.txt] [-input message.txt/-length 512] -output encrypted.txt")
	flag.BoolVar(&decMode, "dec", false, "-dec -key key.txt -nonce nonce.txt -input message.txt -output encrypted.txt")
	flag.BoolVar(&testMode, "test", false, "-test")

	flag.StringVar(&inputFile, "input", "", "")
	flag.StringVar(&outputFile, "output", "output.txt", "")
	flag.StringVar(&keyFile, "key", "", "")
	flag.StringVar(&nonceFile, "nonce", "", "")
	flag.IntVar(&length, "length", 0, "intput a 0x00 byte file, with certain length")

	flag.Parse()
}


func genkey() {
	key, err := bb4.GenKey()
	if err != nil {
		panic(err.Error())
	}

	err = ioutil.WriteFile(outputFile, key, 0600)
	if err != nil {
		panic(err.Error())
	}
}

func gennonce() {
	nonce, err := bb4.GenNonce()
	if err != nil {
		panic(err.Error())
	}

	err = ioutil.WriteFile(outputFile, nonce, 0600)
	if err != nil {
		panic(err.Error())
	}
}

func xor() {
	var key []byte
	var nonce []byte
	var input []byte
	var err error

	if keyFile != "" {
		key, err = ioutil.ReadFile(keyFile)
		if err != nil {
			panic(err.Error())
		}
	} else {
		key, err = bb4.GenKey()
		if err != nil {
			panic(err.Error())
		}
	}

	if nonceFile != "" {
		nonce, err = ioutil.ReadFile(nonceFile)
		if err != nil {
			panic(err.Error())
		}
	} else {
		nonce, err = bb4.GenNonce()
		if err != nil {
			panic(err.Error())
		}
	}

	if inputFile != "" {
		input, err = ioutil.ReadFile(inputFile)
		if err != nil {
			panic(err.Error())
		}
	} else if length != 0 {
		input = make([]byte, length)
	}

	var dst []byte = make([]byte, len(input))
	cipher, err := bb4.NewCipher(key, nonce)
	if err != nil {
		panic(err.Error())
	}
	cipher.XORKeyStream(dst, input)

	if outputFile != "" {
		ioutil.WriteFile(outputFile, dst, 0644)
	}
}

func test() {
	var key []byte
	var nonce []byte
	var err error

	if keyFile != "" {
		key, err = ioutil.ReadFile(keyFile)
		if err != nil {
			panic(err.Error())
		}
	} else {
		key, err = bb4.GenKey()
		if err != nil {
			panic(err.Error())
		}
	}

	if nonceFile != "" {
		nonce, err = ioutil.ReadFile(nonceFile)
		if err != nil {
			panic(err.Error())
		}
	} else {
		nonce = make([]byte, chacha20.NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err.Error())
		}
	}

	var input [2048]byte
	var dst []byte = make([]byte,2048)
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err.Error())
	}

	for {
		cipher.XORKeyStream(dst, input[:])
		_, err = os.Stdout.Write(dst)
		if err != nil {
			panic(err.Error())
		}
	}
}

func main() {
	if genKey {
		genkey()
	} else if genNonce {
		gennonce()
	} else if xorMode {
		xor()
	} else if testMode {
		test()
	}
}
