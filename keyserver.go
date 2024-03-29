package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"text/template"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/vendors/aruba"

	"github.com/brianium/mnemonic"
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
	// HTTPServer hosts the HTTP instance
	HTTPServer http.Server
}

// GuestWirelessNetworkFrontendModel provides template data model for the frontend.
type GuestWirelessNetworkFrontendModel struct {
	// NetworkSSID is the network SSID.
	NetworkSSID string
	// NetworkPSK is the current PSK.
	NetworkPSK string
}

// RotateKey rotates the key.
func (srv *GuestWirelessNetworkCredentialServer) RotateKey() error {
	srv.KeyUpdateMutex.Lock()

	for {
		m, err := mnemonic.NewRandom(256, mnemonic.English)
		if err != nil {
			srv.KeyUpdateMutex.Unlock()
			return err
		}

		sentence := m.Sentence()
		if len(sentence) < 63 {
			srv.TemporaryPsk = m.Sentence()
			break
		}
	}

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
func (srv *GuestWirelessNetworkCredentialServer) Initialize(radiusPSK string, networkSSID string, keyInterval int64) {
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
			log.Printf("[RADIUS][Warn] Incoming RADIUS request from %v don't have valid identity. Rejected", r.RemoteAddr)
		} else {
			log.Printf("[RADIUS] Issuing RADIUS response from %v to AP %v", macIdentity, r.RemoteAddr)
			responsePacket = r.Response(radius.CodeAccessAccept)

			srv.KeyUpdateMutex.RLock()
			// For Cisco AiroNet/Meraki
			if err := rfc2868.TunnelPassword_SetString(responsePacket, 0, srv.TemporaryPsk); err != nil {
				log.Printf("[RADIUS][Cisco] Failed to set tunnel password: %v", err)
				responsePacket = r.Response(radius.CodeAccessReject)
			}

			// For Aruba ClearPass MPSK
			if err := aruba.ArubaMPSKPassphrase_AddString(responsePacket, srv.TemporaryPsk); err != nil {
				log.Printf("[RADIUS][Aruba] Failed to set MPSK: %v", err)
				responsePacket = r.Response(radius.CodeAccessReject)
			}
			srv.KeyUpdateMutex.RUnlock()
		}

		w.Write(responsePacket)
	}

	httpRequestHandler := func(w http.ResponseWriter, r *http.Request) {
		var model GuestWirelessNetworkFrontendModel

		srv.KeyUpdateMutex.RLock()
		model.NetworkPSK = template.HTMLEscapeString(srv.TemporaryPsk)
		model.NetworkSSID = template.HTMLEscapeString(networkSSID)
		srv.KeyUpdateMutex.RUnlock()

		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			log.Printf("[HTTP] Failed to parse HTML template: %v", err)
			w.WriteHeader(500)
			return
		}

		t.Execute(w, model)
	}

	srv.Server = radius.PacketServer{
		Handler:      radius.HandlerFunc(radiusRequestHandler),
		SecretSource: radius.StaticSecretSource([]byte(radiusPSK)),
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(httpRequestHandler))
	mux.Handle("/index.html", http.HandlerFunc(httpRequestHandler))

	srv.HTTPServer = http.Server{
		Addr:    ":8089",
		Handler: mux,
	}
}

// Run starts the RADIUS server instance.
func (srv *GuestWirelessNetworkCredentialServer) Run() {
	// Key rotation housekeeper
	go srv.KeyUpdateRunner()

	// RADIUS server instance
	go func() {
		if err := srv.Server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// HTTP server instance
	go func() {
		if err := srv.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
}

// Application entry point
func main() {
	var radiusPsk string
	flag.StringVar(&radiusPsk, "key", "", "RADIUS pre-shared key")

	var networkSSID string
	flag.StringVar(&networkSSID, "ssid", "", "Wireless network SSID")

	var keyRotationInterval int64
	flag.Int64Var(&keyRotationInterval, "interval", 7200, "Key rotation interval")

	flag.Parse()
	if radiusPsk == "" {
		log.Fatal("[APP] Missing RADIUS pre-shared key")
	}

	if networkSSID == "" {
		log.Fatal("[APP] Missing network SSID")
	}

	pskServer := GuestWirelessNetworkCredentialServer{}
	pskServer.Initialize(radiusPsk, networkSSID, keyRotationInterval)

	log.Printf("[APP] Starting PSK distribution RADIUS server on :1812")
	log.Printf("[APP] Starting PSK distribution HTTP server on :8089")
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

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pskServer.HTTPServer.Shutdown(ctx); err != nil {
		log.Printf("[APP] Failed to gracefully shutdown HTTP server")
	}

	// Cancel the rotation task too
	pskServer.TerminationChan <- true
	log.Printf("[APP] PSK distribution RADIUS server shutting down")
}
