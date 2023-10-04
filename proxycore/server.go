package proxycore

import (
	"chimney-go2/configure"
	"chimney-go2/utils"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TlsServer interface {
	ListenAndServeTLS() error
}

type tlsServerHolder struct {
	Config configure.AppConfig
	Pem    string
	Key    string
}

var values = []string{
	"X-Client-Ip",
	"HTTP_CLIENT_IP",
	"HTTP_X_FORWARDED_FOR",
}

func (ts *tlsServerHolder) handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer dest_conn.Close()
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	defer client_conn.Close()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go transfer(dest_conn, client_conn, &wg)
	go transfer(client_conn, dest_conn, &wg)
	wg.Wait()
}
func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup) {
	io.Copy(destination, source)
	wg.Done()
}
func (ts *tlsServerHolder) handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	ts.copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
func (ts *tlsServerHolder) copyHeader(dst, src http.Header) {

	for k, vv := range src {

		flag := false
		key := strings.ToLower(k)
		for _, v := range values {
			ip := strings.ToLower(v)
			if strings.Contains(key, ip) {
				flag = true
				break
			}
		}

		if flag {
			dst.Add(k, "ip")
			continue
		}

		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (ts *tlsServerHolder) ListenAndServeTLS() error {
	serverHost := net.JoinHostPort(ts.Config.Server, strconv.Itoa(int(ts.Config.ServerPort)))
	server := &http.Server{
		Addr: serverHost,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				ts.handleTunneling(w, r)
			} else {
				ts.handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	err := server.ListenAndServeTLS(ts.Pem, ts.Key)
	log.Print("listen tls failed: ", err)
	return err
}

func NewTlsServer(config configure.AppConfig) (TlsServer, error) {
	certPath, err := utils.RetrieveCertsPath()
	if err != nil {
		log.Print("can not get cert path failed!", err)
		return nil, err
	}

	pemPath := certPath + "/server.pem"
	keyPath := certPath + "/server.key"

	tlsServer := &tlsServerHolder{
		Pem: pemPath,
		Key: keyPath,
	}

	return tlsServer, nil
}
