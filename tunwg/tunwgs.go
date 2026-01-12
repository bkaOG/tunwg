package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ntnj/tunwg/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func tunwgServer() {
	flag.Parse()
	if internal.GetListenPort() <= 0 {
		log.Fatalf("TUNWG_PORT needs to be set")
	} else if internal.ServerIp() == "" {
		log.Fatalf("TUNWG_IP needs to be set")
	}
	if err := internal.Initialize(); err != nil {
		log.Fatalf("failed to initialize: %v", err)
	}
	
	go globalPersist.loadFromDisk()
	go globalPersist.backgroundWriter(time.Minute)
	go internal.BackgroundLogger(10 * time.Second)
	
	httpPort := fmt.Sprintf(":%d", internal.GetHttpPort())
	mux := createServerMux()
	log.Printf("tunwg server starting on %s", httpPort)
	log.Fatalf("failed to run: %v", http.ListenAndServe(httpPort, mux))
}

func allowUserKey(key wgtypes.Key, endpoint string) error {
	ipc := []string{
		"public_key=" + hex.EncodeToString(key[:]),
		fmt.Sprintf("allowed_ip=%s/128", internal.GetIPForKey(key)),
	}
	if endpoint != "" {
		ipc = append(ipc, "endpoint="+endpoint)
	}
	return internal.WgSetIpc(ipc)
}

func createServerMux() http.Handler {
	mux := http.NewServeMux()
	
	// API endpoints
	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if authKey, reqKey := internal.AuthKey(), r.Header.Get("X-Authorization"); authKey != "" && authKey != reqKey {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reqBytes, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req := internal.AddPeerReq{}
		if err := json.Unmarshal(reqBytes, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		clientKey, err := wgtypes.NewKey(req.Key)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := allowUserKey(clientKey, ""); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		globalPersist.markDirty()
		key := internal.GetPublicKey()
		resp := internal.AddPeerResp{
			Key:      key[:],
			Endpoint: fmt.Sprintf("%v:%v", internal.ServerIp(), internal.GetListenPort()),
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	})
	
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		if proto := r.Header.Get("Upgrade"); proto != "udp-relay" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "udp-relay")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, _, err := h.Hijack()
		if err != nil {
			log.Printf("hijack error: %v", err)
			return
		}
		defer conn.Close()
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			log.Printf("relay listen error: %v", err)
			return
		}
		if err := internal.RelayServer(conn, udpConn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: internal.GetListenPort()}); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("relay error: %v", err)
		}
	})
	
	// Default handler - proxy to client via wireguard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			http.Error(w, "No host specified", http.StatusBadRequest)
			return
		}
		
		// Check if this is for the API domain
		if strings.HasSuffix(host, internal.ApiDomain()) || host == internal.ApiDomain() {
			// This should have been handled by specific routes above
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		
		// Proxy to client
		addr, err := getIPForDomain(host)
		if err != nil {
			log.Printf("dispatch error for %s: %v", host, err)
			http.Error(w, "Unable to route request", http.StatusBadGateway)
			return
		}
		
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				log.Printf("[%v] %v %v%v %v", time.Now(), pr.In.Method, pr.In.Host, pr.In.URL.Path, pr.In.RemoteAddr)
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = addr.String()
				pr.SetXForwarded()
			},
			Transport: &http.Transport{
				DialContext: internal.DialWg,
			},
		}
		proxy.ServeHTTP(w, r)
	})
	
	return mux
}

func getIPForDomain(sniName string) (*netip.AddrPort, error) {
	encodedIP, matched := strings.CutSuffix(sniName, "."+internal.ApiDomain())
	if !matched {
		cname, err := net.LookupCNAME(sniName)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup cname %v: %v", sniName, err)
		}
		log.Printf("got cname: %v", cname)
		// CNAME can contain a dot the end
		cname, _ = strings.CutSuffix(cname, ".")
		encodedIP, matched = strings.CutSuffix(cname, "."+internal.ApiDomain())
		if !matched {
			return nil, fmt.Errorf("no proper suffix: %v", sniName)
		}
	}
	splits := strings.Split(encodedIP, ".")
	encodedIP = splits[len(splits)-1]
	addr := internal.LookupEncodedIPPort(encodedIP)
	if addr == nil {
		return nil, fmt.Errorf("error in dispatching: %v", sniName)
	}
	return addr, nil
}

// Persist last seen endpoint to disk
// This enables almost instant reconnect after server restart.
var globalPersist = &persistPeers{}

type persistPeers struct {
	dirty atomic.Bool
	peers map[string]struct {
		Endpoint string
	}
}

func (p *persistPeers) markDirty() {
	p.dirty.Store(true)
}

func (p *persistPeers) backgroundWriter(d time.Duration) {
	var lastWritten time.Time
	for range time.Tick(d) {
		if !p.dirty.Swap(false) && time.Since(lastWritten) < 15*time.Minute {
			continue
		}
		log.Println("writing peers to disk")
		if err := p.writeToDisk(); err != nil {
			log.Printf("error writing peers: %v", err)
		}
		lastWritten = time.Now()
	}
}

func (p *persistPeers) writeToDisk() error {
	dev, err := internal.GetWgDeviceInfo()
	if err != nil {
		return err
	}
	p.peers = make(map[string]struct{ Endpoint string })
	for _, peer := range dev.Peers {
		if time.Since(peer.LastHandshakeTime) < 15*time.Minute {
			// Only write peers who were connected in the last 15 minutes.
			p.peers[string(peer.PublicKey.String())] = struct{ Endpoint string }{
				Endpoint: peer.Endpoint.String(),
			}
		}
	}
	log.Printf("peers to write: %+v", p.peers)
	data, err := json.Marshal(p.peers)
	if err != nil {
		return err
	}
	_ = os.Mkdir(filepath.Join(internal.Keystorage(), "server"), 0o700)
	return os.WriteFile(filepath.Join(internal.Keystorage(), "server/peers.json"), data, 0o600)
}

func (p *persistPeers) loadFromDisk() {
	p.peers = make(map[string]struct{ Endpoint string })
	data, err := os.ReadFile(filepath.Join(internal.Keystorage(), "server/peers.json"))
	if err != nil {
		log.Printf("error reading file: %v", err)
		return
	}
	if err := json.Unmarshal(data, &p.peers); err != nil {
		log.Printf("error unmarshaling: %v", err)
		return
	}
	for k, v := range p.peers {
		key, err := wgtypes.ParseKey(k)
		if err != nil {
			log.Printf("error parsing key: %v", err)
			continue
		}
		// TODO: these writes could be combined to one IPC operation
		if err := allowUserKey(key, v.Endpoint); err != nil {
			log.Printf("error allowing user: %v", err)
		}
	}
}
