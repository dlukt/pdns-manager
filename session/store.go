package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sync"

	"github.com/rs/xid"
)

// Store manages user sessions in memory.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]string // sessionID -> userID
	gcm      cipher.AEAD
}

// NewStore creates a new Store using the provided key. The key is hashed to
// 32 bytes and used for AES-GCM encryption of session IDs stored in cookies.
func NewStore(key []byte) *Store {
	hash := sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &Store{
		sessions: make(map[string]string),
		gcm:      gcm,
	}
}

// Create registers a session for the given user ID and returns an encrypted
// cookie value representing the session ID.
func (s *Store) Create(userID string) (string, error) {
	sid := xid.New().String()
	s.mu.Lock()
	s.sessions[sid] = userID
	s.mu.Unlock()
	return s.encrypt(sid)
}

// Get returns the user ID for the provided encrypted session cookie.
func (s *Store) Get(cookie string) (string, bool) {
	sid, err := s.decrypt(cookie)
	if err != nil {
		return "", false
	}
	s.mu.RLock()
	uid, ok := s.sessions[sid]
	s.mu.RUnlock()
	return uid, ok
}

// Delete removes the session associated with the given encrypted cookie.
func (s *Store) Delete(cookie string) {
	sid, err := s.decrypt(cookie)
	if err != nil {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

func (s *Store) encrypt(plain string) (string, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := s.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Store) decrypt(enc string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	nonceSize := s.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", io.ErrUnexpectedEOF
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
