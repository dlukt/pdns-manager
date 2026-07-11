package config

import (
	"sync"
	"testing"
)

// TestConcurrentAccess guards against the "concurrent map writes" fatal that
// Viper would otherwise raise when PDNS settings are mutated from parallel HTTP
// handlers. Run with -race.
func TestConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			SetPDNSAPIURL("https://powerdns.example/api/v1")
		}()
		go func() {
			defer wg.Done()
			SetPDNSAPIKey("rotate-me")
		}()
		go func() {
			defer wg.Done()
			_ = PDNSAPIURL()
			_ = PDNSAPIKey()
			_ = DSN()
			_ = SMTPAddr()
		}()
	}
	wg.Wait()
}
