package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/beevik/etree"
	"io"
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
	fmt.Printf("gcm Key Type: %T\n", key)
	fmt.Printf("gcm Key Value: %v\n", key)
	if encryptedKeyEl := ciphertextEl.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		var err error
		fmt.Printf("encryptedKeyEl Type: %T\n", encryptedKeyEl)
		fmt.Printf("encryptedKeyEl Value: %v\n", encryptedKeyEl)
		key, err = Decrypt(key, encryptedKeyEl)

		fmt.Printf("gcm new Key Type: %T\n", key)
		fmt.Printf("gcm new Key Value: %v\n", key)
		if err != nil {
			return nil, err
		}
	}

	keyBuf, ok := key.([]byte)

	if !ok {
		return nil, ErrIncorrectKeyType("[]byte")
	}
	if len(keyBuf) != e.KeySize() {
		return nil, ErrIncorrectKeyLength(e.KeySize())
	}

	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	plainText, err := aesgcm.Open(nil, nonce, keyBuf, nil)
	if err != nil {
		return nil, err
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
