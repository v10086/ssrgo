package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type CipherInfo struct {
	KeyLen int
	IvLen  int
}

var methodSupported = map[string]CipherInfo{
	"none":                    {16, 0},
	"rc4":                     {16, 0},
	"rc4-md5":                 {16, 16},
	"rc4-md5-6":               {16, 6},
	"aes-128-cfb":             {16, 16},
	"aes-192-cfb":             {24, 16},
	"aes-256-cfb":             {32, 16},
	"bf-cfb":                  {16, 8},
	"camellia-128-cfb":        {16, 16},
	"camellia-192-cfb":        {24, 16},
	"camellia-256-cfb":        {32, 16},
	"cast5-cfb":               {16, 8},
	"des-cfb":                 {8, 8},
	"idea-cfb":                {16, 8},
	"rc2-cfb":                 {16, 8},
	"seed-cfb":                {16, 16},
	"aes-128-ctr":             {16, 16},
	"aes-192-ctr":             {24, 16},
	"aes-256-ctr":             {32, 16},
	"chacha20":                {32, 8},
	"chacha20-ietf":           {32, 12},
	"aes-128-gcm":             {16, 12},
	"aes-192-gcm":             {24, 12},
	"aes-256-gcm":             {32, 12},
	"chacha20-poly1305":       {32, 8},
	"chacha20-ietf-poly1305":  {32, 12},
	"xchacha20-ietf-poly1305": {32, 24},
}

type Encryptor struct {
	password   string
	method     string
	key        []byte
	sendIV     []byte
	recvIV     []byte
	ivSent     bool
	sendCipher Cipher
	recvCipher Cipher
	onceMode   bool
}

type Cipher interface {
	Update(data []byte) ([]byte, error)
}

type NoneEncipher struct{}

func (n *NoneEncipher) Update(data []byte) ([]byte, error) {
	return data, nil
}

type RC4Encipher struct {
	s [256]byte
	i int
	j int
}

func NewRC4Encipher(key []byte) *RC4Encipher {
	r := &RC4Encipher{}
	for i := 0; i < 256; i++ {
		r.s[i] = byte(i)
	}
	j := 0
	keyLen := len(key)
	for i := 0; i < 256; i++ {
		j = (j + int(r.s[i]) + int(key[i%keyLen])) % 256
		r.s[i], r.s[j] = r.s[j], r.s[i]
	}
	r.i = 0
	r.j = 0
	return r
}

func (r *RC4Encipher) Update(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for y := 0; y < len(data); y++ {
		r.i = (r.i + 1) % 256
		r.j = (r.j + int(r.s[r.i])) % 256
		r.s[r.i], r.s[r.j] = r.s[r.j], r.s[r.i]
		out[y] = data[y] ^ r.s[(int(r.s[r.i])+int(r.s[r.j]))%256]
	}
	return out, nil
}

type CfbEncipher struct {
	stream cipher.Stream
}

func NewCfbEncipher(method string, key, iv []byte) (*CfbEncipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	stream := cipher.NewCFBEncrypter(block, ivCopy)
	return &CfbEncipher{stream: stream}, nil
}

func (c *CfbEncipher) Update(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]byte, len(data))
	c.stream.XORKeyStream(out, data)
	return out, nil
}

type CfbDecipher struct {
	stream cipher.Stream
}

func NewCfbDecipher(method string, key, iv []byte) (*CfbDecipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	stream := cipher.NewCFBDecrypter(block, ivCopy)
	return &CfbDecipher{stream: stream}, nil
}

func (c *CfbDecipher) Update(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]byte, len(data))
	c.stream.XORKeyStream(out, data)
	return out, nil
}

type CtrEncipher struct {
	method  string
	key     []byte
	nonce   []byte
	counter uint64
}

func NewCtrEncipher(method string, key, iv []byte) (*CtrEncipher, error) {
	return &CtrEncipher{
		method:  method,
		key:     key,
		nonce:   append([]byte{}, iv...),
		counter: 0,
	}, nil
}

func (c *CtrEncipher) Update(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	switch c.method {
	case "chacha20":
		key, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(data))
		key.XORKeyStream(result, data)
		return result, nil
	case "chacha20-ietf":
		key, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
		if err != nil {
			return nil, err
		}
		result := make([]byte, len(data))
		key.SetCounter(uint32(c.counter))
		key.XORKeyStream(result, data)
		c.counter += uint64(len(data))
		return result, nil
	default:
		block, err := aes.NewCipher(c.key)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, aes.BlockSize)
		binary.BigEndian.PutUint64(iv[:8], c.counter)
		copy(iv[8:], c.nonce[8:])
		stream := cipher.NewCTR(block, iv)
		result := make([]byte, len(data))
		stream.XORKeyStream(result, data)
		c.counter += uint64((len(data) + aes.BlockSize - 1) / aes.BlockSize)
		return result, nil
	}
}

type AEADEncipher struct {
	algorithm   string
	subkey      []byte
	nonce       []byte
	chunkID     uint64
	encipherAll bool
}

func NewAEADEncipher(algorithm, key, salt string, all bool) (*AEADEncipher, error) {
	var keyLen int
	var nonceLen int

	switch algorithm {
	case "aes-128-gcm":
		keyLen = 16
		nonceLen = 12
	case "aes-192-gcm":
		keyLen = 24
		nonceLen = 12
	case "aes-256-gcm":
		keyLen = 32
		nonceLen = 12
	case "chacha20-poly1305":
		keyLen = 32
		nonceLen = 8
	case "chacha20-ietf-poly1305":
		keyLen = 32
		nonceLen = 12
	case "xchacha20-ietf-poly1305":
		keyLen = 32
		nonceLen = 24
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm: %s", algorithm)
	}

	subkey := make([]byte, keyLen)
	h := hkdf.New(sha256.New, []byte(key), []byte(salt), []byte("ss-subkey"))
	if _, err := h.Read(subkey); err != nil {
		return nil, fmt.Errorf("failed to derive subkey: %v", err)
	}

	return &AEADEncipher{
		algorithm:   algorithm,
		subkey:      subkey,
		nonce:       make([]byte, nonceLen),
		chunkID:     0,
		encipherAll: all,
	}, nil
}

func (a *AEADEncipher) Update(data []byte) ([]byte, error) {
	if a.encipherAll {
		return a.aeadEncryptAll(data)
	}
	return a.aeadChunkEncrypt(data)
}

func (a *AEADEncipher) getCipher() (cipher.AEAD, error) {
	switch a.algorithm {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(a.subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-poly1305":
		return chacha20poly1305.New(a.subkey)
	case "chacha20-ietf-poly1305":
		return chacha20poly1305.New(a.subkey)
	case "xchacha20-ietf-poly1305":
		return chacha20poly1305.NewX(a.subkey)
	default:
		return nil, fmt.Errorf("unsupported AEAD algorithm: %s", a.algorithm)
	}
}

func (a *AEADEncipher) aeadEncryptAll(payload []byte) ([]byte, error) {
	aead, err := a.getCipher()
	if err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nil, a.nonce, payload, nil)
	return encrypted, nil
}

func (a *AEADEncipher) aeadChunkEncrypt(data []byte) ([]byte, error) {
	aead, err := a.getCipher()
	if err != nil {
		return nil, err
	}

	var result []byte
	for len(data) > 0 {
		chunkSize := len(data)
		if chunkSize > 0x3FFF {
			chunkSize = 0x3FFF
		}

		plen := make([]byte, 2)
		binary.BigEndian.PutUint16(plen, uint16(chunkSize))

		plenEnc := aead.Seal(nil, a.nonce, plen, nil)
		a.nonceIncrement()

		chunk := data[:chunkSize]
		chunkEnc := aead.Seal(nil, a.nonce, chunk, nil)
		a.nonceIncrement()

		result = append(result, plenEnc...)
		result = append(result, chunkEnc...)

		data = data[chunkSize:]
		a.chunkID++
	}

	return result, nil
}

func (a *AEADEncipher) nonceIncrement() {
	for i := 0; i < len(a.nonce); i++ {
		a.nonce[i]++
		if a.nonce[i] != 0 {
			break
		}
	}
}

type AEADDecipher struct {
	*AEADEncipher
	tail []byte
}

func NewAEADDecipher(algorithm, key, salt string, all bool) (*AEADDecipher, error) {
	enc, err := NewAEADEncipher(algorithm, key, salt, all)
	if err != nil {
		return nil, err
	}
	return &AEADDecipher{
		AEADEncipher: enc,
		tail:         nil,
	}, nil
}

func (a *AEADDecipher) Update(data []byte) ([]byte, error) {
	if a.encipherAll {
		return a.aeadDecryptAll(data)
	}
	return a.aeadChunkDecrypt(data)
}

func (a *AEADDecipher) aeadDecryptAll(payload []byte) ([]byte, error) {
	aead, err := a.getCipher()
	if err != nil {
		return nil, err
	}
	decrypted, err := aead.Open(nil, a.nonce, payload, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (a *AEADDecipher) aeadChunkDecrypt(data []byte) ([]byte, error) {
	aead, err := a.getCipher()
	if err != nil {
		return nil, err
	}

	if len(a.tail) > 0 {
		data = append(a.tail, data...)
		a.tail = nil
	}

	var result []byte
	for len(data) > 0 {
		minLen := 2*16 + 2
		if len(data) < minLen {
			a.tail = data
			break
		}

		plenEncLen := 16 + 2
		plenEnc := data[:plenEncLen]
		data = data[plenEncLen:]

		plen, err := aead.Open(nil, a.nonce, plenEnc, nil)
		if err != nil {
			return nil, fmt.Errorf("AEAD decrypt error: %v", err)
		}
		a.nonceIncrement()

		if len(plen) != 2 {
			return nil, fmt.Errorf("invalid payload length")
		}

		payloadLen := binary.BigEndian.Uint16(plen) & 0x3FFF
		payloadEncLen := int(payloadLen) + 16

		if len(data) < payloadEncLen {
			a.tail = append(plenEnc, data...)
			break
		}

		payloadEnc := data[:payloadEncLen]
		data = data[payloadEncLen:]

		payload, err := aead.Open(nil, a.nonce, payloadEnc, nil)
		if err != nil {
			return nil, fmt.Errorf("AEAD decrypt error: %v", err)
		}
		a.nonceIncrement()

		result = append(result, payload...)
		a.chunkID++
	}

	return result, nil
}

func NewEncryptor(password, method string, onceMode bool) (*Encryptor, error) {
	method = strings.ToLower(method)
	info, ok := methodSupported[method]
	if !ok {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	key, _, err := EVPBytesToKey(password, info.KeyLen, info.IvLen)
	if err != nil {
		return nil, err
	}

	e := &Encryptor{
		password: password,
		method:   method,
		key:      key,
		ivSent:   false,
		onceMode: onceMode,
	}

	return e, nil
}

func EVPBytesToKey(password string, keyLen, ivLen int) (key []byte, iv []byte, err error) {
	var m [][]byte
	data := []byte(password)
	count := 0
	i := 0

	for count < keyLen+ivLen {
		var d []byte
		if i > 0 {
			d = append(m[i-1], data...)
		} else {
			d = data
		}
		hash := md5.Sum(d)
		m = append(m, hash[:])
		count += len(hash)
		i++
	}

	var ms []byte
	for _, buf := range m {
		ms = append(ms, buf...)
	}

	key = make([]byte, keyLen)
	copy(key, ms[:keyLen])
	iv = make([]byte, ivLen)
	if ivLen > 0 {
		copy(iv, ms[keyLen:keyLen+ivLen])
	}

	return key, iv, nil
}

func (e *Encryptor) InitForSend() error {
	info := methodSupported[e.method]
	iv := make([]byte, info.IvLen)
	if info.IvLen > 0 {
		if _, err := rand.Read(iv); err != nil {
			return err
		}
	}
	e.sendIV = iv
	e.ivSent = false

	cipher, err := e.createCipher(true, iv)
	if err != nil {
		return err
	}
	e.sendCipher = cipher
	return nil
}

func (e *Encryptor) InitForRecv(iv []byte) error {
	e.recvIV = append([]byte{}, iv...)

	cipher, err := e.createCipher(false, iv)
	if err != nil {
		return err
	}
	e.recvCipher = cipher
	return nil
}

func (e *Encryptor) createCipher(isSend bool, iv []byte) (Cipher, error) {
	switch e.method {
	case "none":
		return &NoneEncipher{}, nil
	case "rc4":
		// Pure rc4: use key directly, no IV, no MD5 derivation, no 1024-byte discard (per PHP version)
		return NewRC4Encipher(e.key), nil
	case "rc4-md5", "rc4-md5-6":
		// rc4-md5: key = md5(key + iv)
		rc4Key := md5.Sum(append(e.key, iv...))
		return NewRC4Encipher(rc4Key[:]), nil
	case "aes-128-cfb", "aes-192-cfb", "aes-256-cfb":
		if isSend {
			return NewCfbEncipher(e.method, e.key, iv)
		}
		return NewCfbDecipher(e.method, e.key, iv)
	case "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "chacha20", "chacha20-ietf":
		return NewCtrEncipher(e.method, e.key, iv)
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
		salt := string(iv)
		if isSend {
			return NewAEADEncipher(e.method, string(e.key), salt, e.onceMode)
		}
		return NewAEADDecipher(e.method, string(e.key), salt, e.onceMode)
	default:
		return nil, fmt.Errorf("unsupported method: %s", e.method)
	}
}

func (e *Encryptor) Encrypt(buffer []byte) ([]byte, error) {
	result, err := e.sendCipher.Update(buffer)
	if err != nil {
		return nil, err
	}
	if !e.ivSent {
		info := methodSupported[e.method]
		if info.IvLen > 0 {
			result = append(e.sendIV, result...)
		}
		e.ivSent = true
	}
	return result, nil
}

func (e *Encryptor) Decrypt(buffer []byte) ([]byte, error) {
	if e.recvCipher == nil {
		info := methodSupported[e.method]
		ivLen := info.IvLen
		if len(buffer) < ivLen {
			return nil, fmt.Errorf("buffer too short for IV")
		}
		iv := buffer[:ivLen]
		buffer = buffer[ivLen:]
		if err := e.InitForRecv(iv); err != nil {
			return nil, err
		}
	}
	return e.recvCipher.Update(buffer)
}

func (e *Encryptor) GetKey() []byte {
	return e.key
}

func (e *Encryptor) GetSendIV() []byte {
	return e.sendIV
}

func (e *Encryptor) GetRecvIV() []byte {
	return e.recvIV
}

func GetCipherLen(method string) (keyLen, ivLen int) {
	info, ok := methodSupported[strings.ToLower(method)]
	if !ok {
		return 0, 0
	}
	return info.KeyLen, info.IvLen
}

func ComputeHMAC(hashFunc string, data, key []byte) []byte {
	var h func() hash.Hash
	switch hashFunc {
	case "md5":
		h = md5.New
	case "sha1":
		h = sha1.New
	case "sha256":
		h = sha256.New
	default:
		h = md5.New
	}

	hmac := hmac.New(h, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func HashData(hashFunc string, data []byte) []byte {
	switch hashFunc {
	case "md5":
		h := md5.Sum(data)
		return h[:]
	case "sha1":
		h := sha1.Sum(data)
		return h[:]
	case "sha256":
		h := sha256.Sum256(data)
		return h[:]
	default:
		h := md5.Sum(data)
		return h[:]
	}
}

func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytesRepeat(byte(padding), padding)
	// Make a copy to avoid modifying the original slice's underlying array
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	copy(padded[len(data):], padtext)
	return padded
}

func PKCS7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func bytesRepeat(b byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = b
	}
	return result
}

func AESECBEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := PKCS7Pad(plaintext, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(encrypted[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return encrypted, nil
}

func AESECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	return PKCS7Unpad(decrypted), nil
}

// AES-ECB encrypt exactly one block (16 bytes) without padding
func AESECBEncryptBlock(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) != aes.BlockSize {
		return nil, fmt.Errorf("plaintext must be exactly 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, aes.BlockSize)
	block.Encrypt(encrypted, plaintext)
	return encrypted, nil
}

// AES-ECB decrypt exactly one block (16 bytes) without padding
func AESECBDecryptBlock(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) != aes.BlockSize {
		return nil, fmt.Errorf("ciphertext must be exactly 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, aes.BlockSize)
	block.Decrypt(decrypted, ciphertext)
	return decrypted, nil
}
