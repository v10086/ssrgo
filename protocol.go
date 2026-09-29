package main

import (
	"crypto/md5"
	cryptrand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type Protocol interface {
	ClientPreEncrypt(plaindata []byte) ([]byte, error)
	ClientPostDecrypt(plaindata []byte) ([]byte, error)
	ServerPreEncrypt(plaindata []byte) ([]byte, error)
	ServerPostDecrypt(plaindata []byte) ([]byte, error)
}

type OriginProtocol struct{}

func NewOriginProtocol() *OriginProtocol {
	return &OriginProtocol{}
}

func (o *OriginProtocol) ClientPreEncrypt(plaindata []byte) ([]byte, error) {
	return plaindata, nil
}

func (o *OriginProtocol) ClientPostDecrypt(plaindata []byte) ([]byte, error) {
	return plaindata, nil
}

func (o *OriginProtocol) ServerPreEncrypt(plaindata []byte) ([]byte, error) {
	return plaindata, nil
}

func (o *OriginProtocol) ServerPostDecrypt(plaindata []byte) ([]byte, error) {
	return plaindata, nil
}

type ShadowsocksProtocol struct {
	protocol Protocol
}

func NewShadowsocksProtocol(key, iv []byte, protocol string, param []string) (*ShadowsocksProtocol, error) {
	var p Protocol
	switch protocol {
	case "auth_aes128_md5", "auth_aes128_sha1":
		var err error
		p, err = NewAuthAesProtocol(key, iv, protocol, param)
		if err != nil {
			return nil, err
		}
	case "origin", "":
		p = NewOriginProtocol()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return &ShadowsocksProtocol{protocol: p}, nil
}

func (s *ShadowsocksProtocol) ClientPreEncrypt(plaindata []byte) ([]byte, error) {
	return s.protocol.ClientPreEncrypt(plaindata)
}

func (s *ShadowsocksProtocol) ClientPostDecrypt(plaindata []byte) ([]byte, error) {
	return s.protocol.ClientPostDecrypt(plaindata)
}

func (s *ShadowsocksProtocol) ServerPreEncrypt(plaindata []byte) ([]byte, error) {
	return s.protocol.ServerPreEncrypt(plaindata)
}

func (s *ShadowsocksProtocol) ServerPostDecrypt(plaindata []byte) ([]byte, error) {
	return s.protocol.ServerPostDecrypt(plaindata)
}

const (
	unitLen    = 8100
	maxTimeDif = 86400
)

var hashFuncSupported = map[string]string{
	"auth_aes128_md5":  "md5",
	"auth_aes128_sha1": "sha1",
}

type serverInfo struct {
	ConnectionID  uint32
	ConnectionNum uint32
	LocalClientID []byte
}

var globalServerInfo = serverInfo{
	ConnectionID:  0xffffffff,
	ConnectionNum: 0,
}

type AuthAesProtocol struct {
	hashFunc      string
	key           []byte
	recvIV        []byte
	protocol      string
	param         map[string]string
	recvBuf       []byte
	hasRecvHeader bool
	hasSendHeader bool
	recvID        uint32
	packID        uint32
	userKey       []byte
	userID        uint32
	lastRndLen    int
}

func NewAuthAesProtocol(key, iv []byte, protocol string, param []string) (*AuthAesProtocol, error) {
	hashFunc, ok := hashFuncSupported[protocol]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	p := &AuthAesProtocol{
		hashFunc: hashFunc,
		key:      key,
		recvIV:   iv,
		protocol: protocol,
		param:    make(map[string]string),
		recvBuf:  nil,
		recvID:   1,
		packID:   1,
	}

	if len(param) == 0 {
		p.userKey = key
		p.userID = uint32(rand.Intn(0x7fffffff))
	} else {
		var userIDStr string
		for _, v := range param {
			parts := strings.SplitN(v, ":", 2)
			if len(parts) == 2 {
				p.param[parts[0]] = parts[1]
				if userIDStr == "" {
					userIDStr = parts[0]
				}
			}
		}
		if userIDStr != "" {
			fmt.Sscanf(userIDStr, "%d", &p.userID)
		}
		if password, ok := p.param[fmt.Sprintf("%d", p.userID)]; ok {
			p.userKey = HashData(hashFunc, []byte(password))
		} else {
			p.userKey = key
		}
	}

	if globalServerInfo.ConnectionID == 0xffffffff {
		globalServerInfo.ConnectionID = uint32(rand.Intn(0xFFFFFF))
		globalServerInfo.LocalClientID = make([]byte, 4)
		cryptrand.Read(globalServerInfo.LocalClientID)
	}

	globalServerInfo.ConnectionNum++

	return p, nil
}

func (a *AuthAesProtocol) ClientPreEncrypt(plaindata []byte) ([]byte, error) {
	var outBuf []byte
	ognDataLen := len(plaindata)

	if !a.hasSendHeader {
		headLen := a.getHeadSize(plaindata, 30)
		headLen = minInt(len(plaindata), headLen+rand.Intn(32))
		authData := a.authData()
		packed, err := a.packAuthData(authData, plaindata[:headLen])
		if err != nil {
			return nil, err
		}
		outBuf = append(outBuf, packed...)
		plaindata = plaindata[headLen:]
		a.hasSendHeader = true
	}

	for len(plaindata) > unitLen {
		packed, err := a.packData(plaindata[:unitLen])
		if err != nil {
			return nil, err
		}
		outBuf = append(outBuf, packed...)
		plaindata = plaindata[unitLen:]
	}

	packed, err := a.packData(plaindata)
	if err != nil {
		return nil, err
	}
	outBuf = append(outBuf, packed...)
	a.lastRndLen = ognDataLen
	return outBuf, nil
}

func (a *AuthAesProtocol) ClientPostDecrypt(plaindata []byte) ([]byte, error) {
	a.recvBuf = append(a.recvBuf, plaindata...)
	var outBuf []byte

	for len(a.recvBuf) > 4 {
		hmacKey := append([]byte{}, a.userKey...)
		hmacKey = append(hmacKey, byte(a.recvID), byte(a.recvID>>8), byte(a.recvID>>16), byte(a.recvID>>24))

		thisMy := ComputeHMAC(a.hashFunc, a.recvBuf[:2], hmacKey)
		thisMy = thisMy[:2]
		if !bytesEqual(a.recvBuf[2:4], thisMy) {
			return nil, fmt.Errorf("client data HMAC error")
		}

		blockSize := binary.LittleEndian.Uint16(a.recvBuf[:2])
		if blockSize >= 8192 || blockSize < 7 {
			a.recvBuf = nil
			return nil, fmt.Errorf("client_post_decrypt data length error")
		}

		if len(a.recvBuf) < int(blockSize) {
			break
		}

		block := a.recvBuf[:blockSize]
		a.recvBuf = a.recvBuf[blockSize:]

		thisMy = ComputeHMAC(a.hashFunc, block[:len(block)-4], hmacKey)
		thisMy = thisMy[:4]
		if !bytesEqual(block[len(block)-4:], thisMy) {
			a.recvBuf = nil
			return nil, fmt.Errorf("client_post_decrypt checksum error")
		}

		a.recvID++
		pos := int(block[4])
		if pos == 255 {
			pos = int(block[5]) | int(block[6])<<8
		}
		outBuf = append(outBuf, block[pos+4:len(block)-4]...)
	}

	return outBuf, nil
}

func (a *AuthAesProtocol) ServerPreEncrypt(plaindata []byte) ([]byte, error) {
	var outBuf []byte
	ognDataLen := len(plaindata)

	for len(plaindata) > unitLen {
		packed, err := a.packData(plaindata[:unitLen])
		if err != nil {
			return nil, err
		}
		outBuf = append(outBuf, packed...)
		plaindata = plaindata[unitLen:]
	}

	packed, err := a.packData(plaindata)
	if err != nil {
		return nil, err
	}
	outBuf = append(outBuf, packed...)
	a.lastRndLen = ognDataLen
	return outBuf, nil
}

func (a *AuthAesProtocol) ServerPostDecrypt(plaindata []byte) ([]byte, error) {
	a.recvBuf = append(a.recvBuf, plaindata...)
	var outBuf []byte

	if !a.hasRecvHeader {
		if len(a.recvBuf) >= 7 {
			hmacKey := append([]byte{}, a.recvIV...)
			hmacKey = append(hmacKey, a.key...)

			part1 := a.recvBuf[:7]
			part1My := ComputeHMAC(a.hashFunc, []byte{part1[0]}, hmacKey)
			part1My = part1My[:6]
			if !bytesEqual(part1[len(part1)-6:], part1My) {
				return nil, fmt.Errorf("part1 HMAC verification failed")
			}
		}

		if len(a.recvBuf) < 31 {
			return nil, nil
		}

		hmacKey := append([]byte{}, a.recvIV...)
		hmacKey = append(hmacKey, a.key...)

		part2 := a.recvBuf[7:31]
		part2My := ComputeHMAC(a.hashFunc, part2[:20], hmacKey)
		part2My = part2My[:4]
		if !bytesEqual(part2[len(part2)-4:], part2My) {
			return nil, fmt.Errorf("part2 HMAC verification failed")
		}

		uidData := part2[:4]
		uid := binary.LittleEndian.Uint32(uidData)
		a.userID = uid

		userIDStr := fmt.Sprintf("%d", uid)
		if password, ok := a.param[userIDStr]; ok {
			a.userKey = HashData(a.hashFunc, []byte(password))
		} else if len(a.param) == 0 {
			a.userKey = a.key
		} else {
			return nil, fmt.Errorf("user id is unknown")
		}

		part2EncPartKey := md5Sum([]byte(base64Encode(a.userKey) + a.protocol))
		part2EncPartCopy := make([]byte, 16)
		copy(part2EncPartCopy, part2[4:20])
		part2EncPart, err := decryptNoBug(part2EncPartCopy, part2EncPartKey)
		if err != nil {
			return nil, err
		}
		if len(part2EncPart) != 16 {
			return nil, fmt.Errorf("user key error, decrypted length: %d", len(part2EncPart))
		}

		utc := binary.LittleEndian.Uint32(part2EncPart[0:4])
		plen := binary.LittleEndian.Uint16(part2EncPart[12:14])
		rlen := binary.LittleEndian.Uint16(part2EncPart[14:16])

		if uint16(len(a.recvBuf)) < plen {
			return nil, nil
		}

		hmacData := a.recvBuf[:plen-4]
		handshakeMy := ComputeHMAC(a.hashFunc, hmacData, a.userKey)
		handshakeMy = handshakeMy[:4]
		actualHmac := a.recvBuf[plen-4 : plen]

		if !bytesEqual(actualHmac, handshakeMy) {
			return nil, fmt.Errorf("checksum error")
		}

		timeDif := int64(utc) - time.Now().Unix()
		if timeDif < -maxTimeDif || timeDif > maxTimeDif {
			return nil, fmt.Errorf("wrong timestamp")
		}

		outBuf = append(outBuf, a.recvBuf[31+rlen:plen-4]...)
		a.recvBuf = a.recvBuf[plen:]
		a.hasRecvHeader = true
	}

	for len(a.recvBuf) > 4 {
		hmacKey := append([]byte{}, a.userKey...)
		hmacKey = append(hmacKey, byte(a.recvID), byte(a.recvID>>8), byte(a.recvID>>16), byte(a.recvID>>24))

		thisMy := ComputeHMAC(a.hashFunc, a.recvBuf[:2], hmacKey)
		thisMy = thisMy[:2]
		if !bytesEqual(a.recvBuf[2:4], thisMy) {
			return nil, fmt.Errorf("server data HMAC error")
		}

		blockSize := binary.LittleEndian.Uint16(a.recvBuf[:2])
		if blockSize >= 8192 || blockSize < 7 {
			a.recvBuf = nil
			return nil, fmt.Errorf("server_post_decrypt data length error")
		}

		if len(a.recvBuf) < int(blockSize) {
			break
		}

		block := a.recvBuf[:blockSize]
		a.recvBuf = a.recvBuf[blockSize:]

		thisMy = ComputeHMAC(a.hashFunc, block[:len(block)-4], hmacKey)
		thisMy = thisMy[:4]
		if !bytesEqual(block[len(block)-4:], thisMy) {
			a.recvBuf = nil
			return nil, fmt.Errorf("server_post_decrypt checksum error")
		}

		a.recvID++
		pos := int(block[4])
		if pos == 255 {
			pos = int(block[5]) | int(block[6])<<8
		}
		outBuf = append(outBuf, block[pos+4:len(block)-4]...)
	}

	return outBuf, nil
}

func (a *AuthAesProtocol) packData(buf []byte) ([]byte, error) {
	data := append([]byte{0x01}, buf...)

	packLen := len(data) + 8
	packLenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(packLenBuf, uint16(packLen))

	hmacKey := append([]byte{}, a.userKey...)
	hmacKey = append(hmacKey, byte(a.packID), byte(a.packID>>8), byte(a.packID>>16), byte(a.packID>>24))

	thisMy := ComputeHMAC(a.hashFunc, packLenBuf, hmacKey)
	thisMy = thisMy[:2]

	var packed []byte
	packed = append(packed, packLenBuf...)
	packed = append(packed, thisMy...)
	packed = append(packed, data...)

	thisMy = ComputeHMAC(a.hashFunc, packed, hmacKey)
	thisMy = thisMy[:4]
	packed = append(packed, thisMy...)

	a.packID++
	return packed, nil
}

func (a *AuthAesProtocol) packAuthData(authData, buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}

	var rndLen int
	if len(buf) > 400 {
		rndLen = rand.Intn(101)
	} else {
		rndLen = rand.Intn(801)
	}

	data := authData
	dataLen := 7 + 4 + 16 + 4 + rndLen + len(buf) + 4

	var dataBuf []byte
	dataBuf = append(dataBuf, data...)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(dataLen))
	dataBuf = append(dataBuf, lenBuf...)
	rndLenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(rndLenBuf, uint16(rndLen))
	dataBuf = append(dataBuf, rndLenBuf...)

	hmacKey := append([]byte{}, a.recvIV...)
	hmacKey = append(hmacKey, a.key...)

	uidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(uidBuf, a.userID)

	part2EncPartKey := md5Sum([]byte(base64Encode(a.userKey) + a.protocol))

	// PHP uses openssl_encrypt with PKCS7 padding (default), but takes only first 16 bytes
	// dataBuf is exactly 16 bytes (12 auth + 2 plen + 2 rlen)
	encrypted, err := AESECBEncrypt(dataBuf, part2EncPartKey)
	if err != nil {
		return nil, err
	}

	dataBuf = append(uidBuf, encrypted[:16]...)
	handshakeMy := ComputeHMAC(a.hashFunc, dataBuf, hmacKey)
	handshakeMy = handshakeMy[:4]
	dataBuf = append(dataBuf, handshakeMy...)

	checkHead := make([]byte, 1)
	cryptrand.Read(checkHead)
	handshakeMy = ComputeHMAC(a.hashFunc, checkHead, hmacKey)
	handshakeMy = handshakeMy[:6]
	checkHead = append(checkHead, handshakeMy...)

	dataRnd := make([]byte, rndLen)
	cryptrand.Read(dataRnd)

	dataBuf = append(checkHead, dataBuf...)
	dataBuf = append(dataBuf, dataRnd...)
	dataBuf = append(dataBuf, buf...)

	handshakeMy = ComputeHMAC(a.hashFunc, dataBuf, a.userKey)
	handshakeMy = handshakeMy[:4]
	dataBuf = append(dataBuf, handshakeMy...)

	return dataBuf, nil
}

func (a *AuthAesProtocol) authData() []byte {
	utcTime := uint32(time.Now().Unix())

	if globalServerInfo.ConnectionID > 0xff000000 {
		globalServerInfo.LocalClientID = nil
	}
	if globalServerInfo.LocalClientID == nil {
		globalServerInfo.LocalClientID = make([]byte, 4)
		cryptrand.Read(globalServerInfo.LocalClientID)
		globalServerInfo.ConnectionID = uint32(rand.Intn(0xFFFFFF))
	}

	globalServerInfo.ConnectionID++

	var auth []byte
	utcBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(utcBuf, utcTime)
	auth = append(auth, utcBuf...)
	auth = append(auth, globalServerInfo.LocalClientID...)

	cidBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(cidBuf, globalServerInfo.ConnectionID)
	auth = append(auth, cidBuf...)

	return auth
}

func (a *AuthAesProtocol) getHeadSize(buf []byte, defValue int) int {
	if len(buf) < 2 {
		return defValue
	}
	switch buf[0] {
	case 0x01:
		return 7
	case 0x04:
		return 19
	case 0x03:
		return 4 + int(buf[1])
	default:
		return defValue
	}
}

func decryptNoBug(dat, key []byte) ([]byte, error) {
	// PHP implementation:
	// $m = openssl_encrypt($dat , 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
	// $m = $dat . substr($m, 16, 32);
	// return openssl_decrypt($m, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);

	// Step 1: Encrypt dat (16 bytes) with PKCS7 padding -> produces 32 bytes
	m, err := AESECBEncrypt(dat, key)
	if err != nil {
		return nil, err
	}

	// Step 2: Take dat (16 bytes) + second block of encrypted result (16 bytes of encrypted padding)
	// openssl_encrypt of 16 bytes with PKCS7 produces 32 bytes: first 16 is encrypted data, next 16 is encrypted padding
	var m2 []byte
	m2 = append(m2, dat...)
	m2 = append(m2, m[16:32]...) // substr($m, 16, 32)

	// Step 3: Decrypt the 32-byte block
	return AESECBDecrypt(m2, key)
}

func md5Sum(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
