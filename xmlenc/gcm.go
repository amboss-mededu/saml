package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/beevik/etree"
)

// struct implements Decrypter and Encrypter for block ciphers in struct mode
type GCM struct {
	keySize   int
	algorithm string
	cipher    func([]byte) (cipher.Block, error)
}

// KeySize returns the length of the key required.
func (e GCM) KeySize() int {
	return e.keySize
}

// Algorithm returns the name of the algorithm, as will be found
// in an xenc:EncryptionMethod element.
func (e GCM) Algorithm() string {
	return e.algorithm
}

func (e GCM) Encrypt(key interface{}, plaintext []byte) (*etree.Element, error) {
	return nil, nil
}

// Decrypt decrypts an encrypted element with key. If the ciphertext contains an
// EncryptedKey element, then the type of `key` is determined by the registered
// Decryptor for the EncryptedKey element. Otherwise, `key` must be a []byte of
// length KeySize().
func (e GCM) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	block, err := aes.NewCipher(key.([]byte))
	if err != nil {
		return []byte(""), err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte(""), err
	}

	if encryptedKeyEl := ciphertextEl.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		var err error
		key, err = Decrypt(key, encryptedKeyEl)
		if err != nil {
			return nil, err
		}
	}

	plainText, err := aesgcm.Open(nil, nil, key.([]byte), nil)
	if err != nil {
		return []byte(""), err
	}

	return plainText, nil
}

var (
	// AES128GCM implements AES128-GCM mode for encryption and decryption
	AES128GCM BlockCipher = GCM{
		keySize:   16,
		algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
		cipher:    aes.NewCipher,
	}
)

func init() {
	RegisterDecrypter(AES128GCM)
}
