package main

import (
	"context"
	"crypto/rand"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"layeh.com/radius/rfc2865"

	"layeh.com/radius"
	"layeh.com/radius/rfc2868"
)

// GuestWirelessNetworkCredentialServer implements the RADIUS server
// that distributes the identity PSK.
type GuestWirelessNetworkCredentialServer struct {
	// KeyUpdateInterval specifies the key rotation interval in seconds.
	KeyUpdateInterval int64
	// LastUpdate provides the timestamp of last key rotation time.
	LastUpdate time.Time
	// TemporaryPsk holds the current pre-shared key data.
	TemporaryPsk string
	// KeyUpdateMutex provides synchronization primitives across routines.
	KeyUpdateMutex sync.RWMutex
	// TerminationChan notifies shutdown information
	TerminationChan chan bool
	// Server hosts the RADIUS server instance
	Server radius.PacketServer
}

// GenerateRandomASCIIString returns a securely generated random ASCII string.
// It reads random numbers from crypto/rand and searches for printable characters.
// It will return an error if the system's secure random number generator fails to
// function correctly, in which case the caller must not continue.
// From https://gist.github.com/denisbrodbeck/635a644089868a51eccd6ae22b2eb800
func GenerateRandomASCIIString(length int) (string, error) {
	var sb strings.Builder
	l := 0

	for {
		if l >= length {
			return sb.String(), nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			sb.WriteRune(rune(n))
			l++
		}
	}
}

// RotateKey rotates the key.
func (srv *GuestWirelessNetworkCredentialServer) RotateKey() error {
	srv.KeyUpdateMutex.Lock()

	// WPA2 PSK max length is 16 ASCII characters
	key, err := GenerateRandomASCIIString(16)
	if err != nil {
		srv.KeyUpdateMutex.Unlock()
		return err
	}

	srv.TemporaryPsk = key
	srv.LastUpdate = time.Now()

	srv.KeyUpdateMutex.Unlock()
	return nil
}

// KeyUpdateRunner runs the background update task.
func (srv *GuestWirelessNetworkCredentialServer) KeyUpdateRunner() {
	ticker := time.NewTicker(time.Duration(srv.KeyUpdateInterval) * time.Second)
	for {
		select {
		case <-srv.TerminationChan:
			ticker.Stop()
			return
		case <-ticker.C:
			if err := srv.RotateKey(); err != nil {
				log.Printf("[KEYROTATION] Failed to run key rotation: %v", err)
			}
		}
	}
}

// Initialize prepares the RADIUS instance.
func (srv *GuestWirelessNetworkCredentialServer) Initialize(radiusPSK string, keyInterval int64) {
	srv.KeyUpdateInterval = keyInterval
	srv.TerminationChan = make(chan bool)

	// We also need initial key
	if err := srv.RotateKey(); err != nil {
		log.Fatalf("[RADIUS] Failed to generate initial key: %v", err)
	}

	radiusRequestHandler := func(w radius.ResponseWriter, r *radius.Request) {
		// We don't actually care about MAC identity (maybe we will take care of it later)
		// But we need to have one anyway.
		//
		// So at this moment we just check the presence, then blindly accept the request
		// and return the required PSK information.
		responsePacket := r.Response(radius.CodeAccessReject)
		macIdentity := rfc2865.UserPassword_GetString(r.Packet)

		if macIdentity == "" {
			log.Printf("[RADIUS] Incoming RADIUS request from %v don't have valid identity", r.RemoteAddr)
		} else {
			log.Printf("[RADIUS] Issuing RADIUS response from %v to AP %v", macIdentity, r.RemoteAddr)
			responsePacket = r.Response(radius.CodeAccessAccept)

			srv.KeyUpdateMutex.RLock()
			if err := rfc2868.TunnelPassword_SetString(responsePacket, 0, srv.TemporaryPsk); err != nil {
				log.Printf("[RADIUS] Failed to set tunnel password: %v", err)
				responsePacket = r.Response(radius.CodeAccessReject)
			}
			srv.KeyUpdateMutex.RUnlock()
		}

		w.Write(responsePacket)
	}

	srv.Server = radius.PacketServer{
		Handler:      radius.HandlerFunc(radiusRequestHandler),
		SecretSource: radius.StaticSecretSource([]byte(radiusPSK)),
	}
}

// Run starts the RADIUS server instance.
func (srv *GuestWirelessNetworkCredentialServer) Run() {
	// Key rotation housekeeper
	go srv.KeyUpdateRunner()

	// RADIUS server instance
	if err := srv.Server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// Application entry point
func main() {
	pskServer := GuestWirelessNetworkCredentialServer{}
	pskServer.Initialize(`development`, 60)

	log.Printf("[APP] Starting PSK distribution RADIUS server on :1812")
	go pskServer.Run()

	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (pkill -2)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pskServer.Server.Shutdown(ctx); err != nil {
		log.Printf("[APP] Failed to gracefully shutdown RADIUS server")
	}

	// Cancel the rotation task too
	pskServer.TerminationChan <- true
	log.Printf("[APP] PSK distribution RADIUS server shutting down")
}
