// Package service provides the full OpenVPN management layer for TP Panel.
// OpenVPN inbounds run as a separate process (not via Xray core), so this
// service owns PKI generation, config rendering, process lifecycle, and
// certificate revocation.
//
// PKI directory layout (under openvpnBaseDir):
//
//	ca.crt / ca.key          — root CA
//	server.crt / server.key  — server certificate
//	dh.pem                   — Diffie-Hellman parameters
//	ta.key                   — TLS-Auth HMAC-SHA1 secret
//	crl.pem                  — certificate revocation list
//	clients/<name>.crt/.key  — per-client certificates
package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

const (
	openvpnBaseDir    = "/etc/tp-panel/openvpn"
	openvpnPidDir     = "/var/run/tp-panel"
	caCertFile        = "ca.crt"
	caKeyFile         = "ca.key"
	serverCertFile    = "server.crt"
	serverKeyFile     = "server.key"
	dhFile            = "dh.pem"
	tlsAuthFile       = "ta.key"
	crlFile           = "crl.pem"
	clientsSubdir     = "clients"
	openvpnBinDefault = "openvpn"
	rsaKeyBits        = 2048
	certValidityYears = 10
	clientCertDays    = 365
)

// OpenVPNService manages the lifecycle, PKI, and configuration of OpenVPN
// servers running as sidecar processes alongside the TP Panel.
type OpenVPNService struct {
	mu      sync.Mutex
	running map[int]*openvpnInstance
}

type openvpnInstance struct {
	cmd    *exec.Cmd
	cancel func()
}

// NewOpenVPNService creates a new OpenVPN service instance.
func NewOpenVPNService() *OpenVPNService {
	return &OpenVPNService{
		running: make(map[int]*openvpnInstance),
	}
}

// ServerConfig holds the parameters needed to render an OpenVPN server config.
type ServerConfig struct {
	Port        int
	Protocol    string // "udp" or "tcp"
	Subnet      string // e.g. "10.8.0.0"
	Netmask     string // e.g. "255.255.255.0"
	DNS         []string
	Cipher      string // e.g. "AES-256-GCM"
	Auth        string // e.g. "SHA256"
	KeepAlive   int    // seconds
	MaxClients  int
	CertFile    string
	KeyFile     string
	CaFile      string
	DhFile      string
	TlsAuthFile string
	CrlFile     string
}

// ClientCert holds PEM-encoded data for one client.
type ClientCert struct {
	Name      string
	CertPEM   []byte
	KeyPEM    []byte
	CaCertPEM []byte
	TlsAuthPEM []byte
}

// pkiPath returns the full path for a file inside the PKI base directory.
func pkiPath(name string) string {
	return filepath.Join(openvpnBaseDir, name)
}

// pidPath returns the PID file path for a given inbound ID.
func pidPath(inboundID int) string {
	return filepath.Join(openvpnPidDir, fmt.Sprintf("openvpn-%d.pid", inboundID))
}

// logPath returns the log file path for a given inbound ID.
func logPath(inboundID int) string {
	return filepath.Join("/var/log", fmt.Sprintf("tp-panel-openvpn-%d.log", inboundID))
}

// statusPath returns the status log path for a given inbound ID.
func statusPath(inboundID int) string {
	return filepath.Join("/var/log", fmt.Sprintf("tp-panel-openvpn-status-%d.log", inboundID))
}

// ---------------------------------------------------------------------------
// PKI — full initialization
// ---------------------------------------------------------------------------

// InitPKI creates the PKI directory and generates all required artifacts if
// they don't already exist: CA, server cert, DH params, and TLS-Auth key.
// DH generation shells out to `openssl dhparam` (2048-bit); if openssl is
// unavailable a warning is logged and the server config omits the dh line.
func (s *OpenVPNService) InitPKI() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(openvpnBaseDir, 0700); err != nil {
		return fmt.Errorf("openvpn pki: mkdir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(openvpnBaseDir, clientsSubdir), 0700); err != nil {
		return fmt.Errorf("openvpn pki: mkdir clients: %w", err)
	}

	// Step 1: CA
	if _, err := os.Stat(pkiPath(caCertFile)); os.IsNotExist(err) {
		if err := s.generateCA(); err != nil {
			return err
		}
	}

	// Step 2: Server certificate
	if _, err := os.Stat(pkiPath(serverCertFile)); os.IsNotExist(err) {
		if err := s.generateServerCert(); err != nil {
			return err
		}
	}

	// Step 3: DH parameters
	if _, err := os.Stat(pkiPath(dhFile)); os.IsNotExist(err) {
		s.generateDH()
	}

	// Step 4: TLS-Auth key
	if _, err := os.Stat(pkiPath(tlsAuthFile)); os.IsNotExist(err) {
		s.generateTLSAuthKey()
	}

	logger.Info("OpenVPN PKI initialized at", openvpnBaseDir)
	return nil
}

// ensurePKI ensures the PKI is initialized. Callers that already hold s.mu
// should NOT call this directly — use InitPKI instead.
func (s *OpenVPNService) ensurePKI() error {
	return s.InitPKI()
}

// generateCA creates a new self-signed CA certificate and private key.
func (s *OpenVPNService) generateCA() error {
	caKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("openvpn pki: generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"TP Panel"},
			CommonName:   "TP Panel CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certValidityYears * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("openvpn pki: create CA cert: %w", err)
	}

	if err := writePEMFile(pkiPath(caCertFile), "CERTIFICATE", caCertDER); err != nil {
		return err
	}
	caKeyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	if err := writePEMFile(pkiPath(caKeyFile), "PRIVATE KEY", caKeyDER); err != nil {
		return err
	}
	return nil
}

// generateServerCert creates a server certificate signed by the CA.
// The certificate has extendedKeyUsage ServerAuth so OpenVPN accepts it.
func (s *OpenVPNService) generateServerCert() error {
	caCert, caKey, err := s.loadCA()
	if err != nil {
		return err
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("openvpn: generate server key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"TP Panel"},
			CommonName:   "TP Panel Server",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certValidityYears * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("openvpn: sign server cert: %w", err)
	}

	if err := writePEMFile(pkiPath(serverCertFile), "CERTIFICATE", certDER); err != nil {
		return err
	}
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	return writePEMFile(pkiPath(serverKeyFile), "PRIVATE KEY", serverKeyDER)
}

// generateDH shells out to `openssl dhparam` to create DH parameters.
// This is slow (30-120s) but is the standard way; Go's standard library
// has no DH parameter generation.
func (s *OpenVPNService) generateDH() {
	outPath := pkiPath(dhFile)
	cmd := exec.Command("openssl", "dhparam", "-out", outPath, "2048")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		logger.Warning("openvpn: openssl dhparam failed, server config will omit DH:", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			logger.Warning("openvpn: openssl dhparam failed:", err)
			return
		}
		logger.Info("openvpn: DH parameters generated at", outPath)
	}()
}

// generateTLSAuthKey creates an HMAC-SHA1 shared secret for tls-auth.
// Format: first line is "OpenVPN Static key V1", followed by 16 hex blocks.
func (s *OpenVPNService) generateTLSAuthKey() {
	var buf [256]byte
	if _, err := rand.Read(buf[:]); err != nil {
		logger.Warning("openvpn: failed to generate TLS-Auth key:", err)
		return
	}

	var b strings.Builder
	b.WriteString("OpenVPN Static key V1\n")
	b.WriteString("-----\n")
	for i := 0; i < 16; i++ {
		chunk := buf[i*16 : (i+1)*16]
		for _, by := range chunk {
			b.WriteString(fmt.Sprintf("%02x", by))
		}
		b.WriteByte('\n')
	}
	b.WriteString("-----\n")

	if err := os.WriteFile(pkiPath(tlsAuthFile), []byte(b.String()), 0600); err != nil {
		logger.Warning("openvpn: write tls-auth key:", err)
		return
	}
	logger.Info("openvpn: TLS-Auth key generated at", pkiPath(tlsAuthFile))
}

// ---------------------------------------------------------------------------
// Client certificate management
// ---------------------------------------------------------------------------

// GenerateClientCert creates a new client certificate signed by the CA and
// saves it to the clients/ subdirectory.
func (s *OpenVPNService) GenerateClientCert(name string) (*ClientCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	caCert, caKey, err := s.loadCA()
	if err != nil {
		return nil, err
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("openvpn: generate client key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"TP Panel"},
			CommonName:   name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(clientCertDays * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("openvpn: sign client cert: %w", err)
	}

	// Save client cert and key to disk.
	clientDir := filepath.Join(openvpnBaseDir, clientsSubdir)
	if err := os.MkdirAll(clientDir, 0700); err != nil {
		return nil, fmt.Errorf("openvpn: mkdir clients: %w", err)
	}
	if err := writePEMFile(filepath.Join(clientDir, name+".crt"), "CERTIFICATE", certDER); err != nil {
		return nil, err
	}
	clientKeyDER, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	if err := writePEMFile(filepath.Join(clientDir, name+".key"), "PRIVATE KEY", clientKeyDER); err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	// Load the TLS-Auth key for embedding in the client config
	var tlsAuthPEM []byte
	if data, err := os.ReadFile(pkiPath(tlsAuthFile)); err == nil {
		tlsAuthPEM = data
	}

	return &ClientCert{
		Name:       name,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		CaCertPEM:  caCertPEM,
		TlsAuthPEM: tlsAuthPEM,
	}, nil
}

// RevokeClientCert revokes a client certificate by adding it to the CRL.
// The CRL is written to crl.pem and OpenVPN reloads it on the next
// connection attempt (or after `openvpn --reload`).
func (s *OpenVPNService) RevokeClientCert(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := filepath.Join(openvpnBaseDir, clientsSubdir, name+".crt")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("openvpn: read client cert for revocation: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("openvpn: decode client cert PEM for revocation")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("openvpn: parse client cert for revocation: %w", err)
	}

	caCert, caKey, err := s.loadCA()
	if err != nil {
		return err
	}

	// Build or load the existing CRL.
	var revokedCerts []x509.RevocationListEntry
	crlPath := pkiPath(crlFile)
	var existingNumber *big.Int
	if existingCRL, readErr := readCRL(crlPath); readErr == nil {
		revokedCerts = existingCRL.RevokedCertificateEntries
		existingNumber = existingCRL.Number
	}

	// Increment the CRL number.
	newNumber := big.NewInt(1)
	if existingNumber != nil {
		newNumber.Add(existingNumber, big.NewInt(1))
	}

	// Append the new revocation entry.
	revokedCerts = append(revokedCerts, x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	})

	// Generate a new CRL signed by the CA.
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: revokedCerts,
		Number:                    newNumber,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(365 * 24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return fmt.Errorf("openvpn: create CRL: %w", err)
	}
	if err := writePEMFile(crlPath, "X509 CRL", crlDER); err != nil {
		return err
	}

	// Remove the cert file (key stays for audit trail).
	_ = os.Remove(certPath)
	logger.Info("OpenVPN: revoked client certificate for", name)
	return nil
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

// DefaultServerConfig returns a ServerConfig with sane defaults derived from
// an inbound's port and the panel's PKI directory.
func DefaultServerConfig(inbound *model.Inbound) *ServerConfig {
	return &ServerConfig{
		Port:        inbound.Port,
		Protocol:    "udp",
		Subnet:      "10.8.0.0",
		Netmask:     "255.255.255.0",
		DNS:         []string{"8.8.8.8", "8.8.4.4"},
		Cipher:      "AES-256-GCM",
		Auth:        "SHA256",
		KeepAlive:   10,
		MaxClients:  100,
		CertFile:    pkiPath(serverCertFile),
		KeyFile:     pkiPath(serverKeyFile),
		CaFile:      pkiPath(caCertFile),
		DhFile:      pkiPath(dhFile),
		TlsAuthFile: pkiPath(tlsAuthFile),
		CrlFile:     pkiPath(crlFile),
	}
}

// GenerateServerConfig produces the full OpenVPN server configuration text.
func (s *OpenVPNService) GenerateServerConfig(inbound *model.Inbound, cfg *ServerConfig) (string, error) {
	if cfg == nil {
		cfg = DefaultServerConfig(inbound)
	}

	var b strings.Builder
	b.WriteString("# TP Panel OpenVPN server configuration\n")
	b.WriteString(fmt.Sprintf("# Inbound ID: %d | Remark: %s\n", inbound.Id, inbound.Remark))
	b.WriteString("\n")

	// Network
	b.WriteString(fmt.Sprintf("port %d\n", cfg.Port))
	b.WriteString(fmt.Sprintf("proto %s\n", cfg.Protocol))
	b.WriteString("dev tun\n")

	// PKI files
	b.WriteString(fmt.Sprintf("ca %s\n", cfg.CaFile))
	b.WriteString(fmt.Sprintf("cert %s\n", cfg.CertFile))
	b.WriteString(fmt.Sprintf("key %s\n", cfg.KeyFile))
	if cfg.DhFile != "" {
		if _, err := os.Stat(cfg.DhFile); err == nil {
			b.WriteString(fmt.Sprintf("dh %s\n", cfg.DhFile))
		}
	}
	if cfg.TlsAuthFile != "" {
		if _, err := os.Stat(cfg.TlsAuthFile); err == nil {
			b.WriteString(fmt.Sprintf("tls-auth %s 0\n", cfg.TlsAuthFile))
		}
	}
	if cfg.CrlFile != "" {
		if _, err := os.Stat(cfg.CrlFile); err == nil {
			b.WriteString(fmt.Sprintf("crl-verify %s\n", cfg.CrlFile))
		}
	}

	// VPN subnet and routing
	b.WriteString(fmt.Sprintf("server %s %s\n", cfg.Subnet, cfg.Netmask))
	b.WriteString("client-to-client\n")
	b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")

	// DNS
	if len(cfg.DNS) > 0 {
		for _, dns := range cfg.DNS {
			b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns))
		}
	}

	// Crypto
	b.WriteString(fmt.Sprintf("cipher %s\n", cfg.Cipher))
	b.WriteString(fmt.Sprintf("auth %s\n", cfg.Auth))
	b.WriteString("tls-version-min 1.2\n")

	// Stability
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString(fmt.Sprintf("keepalive %d %d\n", cfg.KeepAlive, cfg.KeepAlive*3))
	b.WriteString(fmt.Sprintf("max-clients %d\n", cfg.MaxClients))

	// Security hardening
	b.WriteString("user nobody\n")
	b.WriteString("group nogroup\n")
	b.WriteString("remote-cert-tls client\n")

	// Per-client certificate directory. OpenVPN reads per-client config
	// files from this directory (named by CN). Used for client-connect
	// scripts and per-client settings. The directory is created by InitPKI.
	ccdDir := filepath.Join(openvpnBaseDir, "ccd")
	_ = os.MkdirAll(ccdDir, 0700)
	b.WriteString(fmt.Sprintf("client-config-dir %s\n", ccdDir))
	b.WriteString("verify-client-cert require\n")

	// Logging
	logFile := logPath(inbound.Id)
	b.WriteString(fmt.Sprintf("log-append %s\n", logFile))
	statusFile := statusPath(inbound.Id)
	b.WriteString(fmt.Sprintf("status %s 30\n", statusFile))
	b.WriteString("verb 3\n")
	b.WriteString("explicit-exit-notify 1\n")

	return b.String(), nil
}

// GenerateClientOVPN produces a complete .ovpn file for the given client.
func (s *OpenVPNService) GenerateClientOVPN(cfg *ServerConfig, client *ClientCert, serverAddr string) (string, error) {
	if serverAddr == "" {
		serverAddr = "YOUR_SERVER_IP"
	}

	var b strings.Builder
	b.WriteString("# TP Panel OpenVPN client configuration\n")
	b.WriteString("# Generated by TP Panel\n")
	b.WriteString("\n")
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString(fmt.Sprintf("proto %s\n", cfg.Protocol))
	b.WriteString(fmt.Sprintf("remote %s %d\n", serverAddr, cfg.Port))
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString(fmt.Sprintf("cipher %s\n", cfg.Cipher))
	b.WriteString(fmt.Sprintf("auth %s\n", cfg.Auth))
	b.WriteString("tls-version-min 1.2\n")
	if len(client.TlsAuthPEM) > 0 {
		b.WriteString("key-direction 1\n")
	}
	b.WriteString("verb 3\n")
	b.WriteString("\n")

	// Embedded certificates
	b.WriteString("<ca>\n")
	b.WriteString(string(client.CaCertPEM))
	b.WriteString("</ca>\n")
	b.WriteString("<cert>\n")
	b.WriteString(string(client.CertPEM))
	b.WriteString("</cert>\n")
	b.WriteString("<key>\n")
	b.WriteString(string(client.KeyPEM))
	b.WriteString("</key>\n")

	// Embedded TLS-Auth key
	if len(client.TlsAuthPEM) > 0 {
		b.WriteString("<tls-auth>\n")
		b.WriteString(string(client.TlsAuthPEM))
		b.WriteString("</tls-auth>\n")
	}

	return b.String(), nil
}

// ---------------------------------------------------------------------------
// Process lifecycle
// ---------------------------------------------------------------------------

// Start launches an OpenVPN server process for the given inbound.
func (s *OpenVPNService) Start(inbound *model.Inbound, cfg *ServerConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.running[inbound.Id]; exists {
		return nil // already running
	}

	if err := os.MkdirAll(openvpnPidDir, 0755); err != nil {
		return fmt.Errorf("openvpn: mkdir pid dir: %w", err)
	}

	configText, err := s.GenerateServerConfig(inbound, cfg)
	if err != nil {
		return fmt.Errorf("openvpn: generate config: %w", err)
	}

	// Write the config to disk so openvpn can read it.
	configDir := filepath.Join(openvpnBaseDir, fmt.Sprintf("server-%d", inbound.Id))
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("openvpn: mkdir config dir: %w", err)
	}
	configPath := filepath.Join(configDir, "server.conf")
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		return fmt.Errorf("openvpn: write config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, openvpnBinDefault, "--config", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("openvpn: start: %w", err)
	}

	s.running[inbound.Id] = &openvpnInstance{cmd: cmd, cancel: cancel}

	// Write PID file.
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath(inbound.Id), []byte(strconv.Itoa(pid)), 0644); err != nil {
		logger.Warning("openvpn: write pid file:", err)
	}

	logger.Infof("OpenVPN server started for inbound %d (PID %d)", inbound.Id, pid)

	// Reap the process when it exits.
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		delete(s.running, inbound.Id)
		s.mu.Unlock()
		_ = os.Remove(pidPath(inbound.Id))
	}()

	return nil
}

// Stop terminates the OpenVPN server process for the given inbound.
func (s *OpenVPNService) Stop(inboundID int) error {
	s.mu.Lock()
	inst, exists := s.running[inboundID]
	if exists {
		delete(s.running, inboundID)
	}
	s.mu.Unlock()

	if !exists {
		// Try to kill by PID file.
		return s.killByPIDFile(inboundID)
	}

	inst.cancel()
	if inst.cmd.Process != nil {
		if err := inst.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = inst.cmd.Process.Kill()
		}
	}
	_ = os.Remove(pidPath(inboundID))
	logger.Infof("OpenVPN server stopped for inbound %d", inboundID)
	return nil
}

// Status returns whether the OpenVPN server for the given inbound is running.
func (s *OpenVPNService) Status(inboundID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inst, ok := s.running[inboundID]; ok {
		return inst.cmd.Process != nil
	}
	return false
}

// Reload sends SIGHUP to a running OpenVPN process to reload certs/CRL.
func (s *OpenVPNService) Reload(inboundID int) error {
	s.mu.Lock()
	inst, exists := s.running[inboundID]
	s.mu.Unlock()

	if !exists {
		return s.reloadByPIDFile(inboundID)
	}

	if inst.cmd.Process != nil {
		return inst.cmd.Process.Signal(os.Signal(syscall.SIGHUP))
	}
	return fmt.Errorf("openvpn: process not running for inbound %d", inboundID)
}

func (s *OpenVPNService) killByPIDFile(inboundID int) error {
	pidBytes, err := os.ReadFile(pidPath(inboundID))
	if err != nil {
		return nil // no PID file, nothing to kill
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = proc.Kill()
	_ = os.Remove(pidPath(inboundID))
	return nil
}

func (s *OpenVPNService) reloadByPIDFile(inboundID int) error {
	pidBytes, err := os.ReadFile(pidPath(inboundID))
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	return proc.Signal(syscall.SIGHUP)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *OpenVPNService) loadCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	caCertPEM, err := os.ReadFile(pkiPath(caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: read CA cert: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("openvpn: decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: parse CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(pkiPath(caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: read CA key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("openvpn: decode CA key PEM")
	}
	caKeyInterface, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: parse CA key: %w", err)
	}
	caKey, ok := caKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("openvpn: CA key is not RSA")
	}

	return caCert, caKey, nil
}

func readCRL(path string) (*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode CRL PEM")
	}
	return x509.ParseRevocationList(block.Bytes)
}

func writePEMFile(path, blockType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("openvpn: write %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}

// generateOpenvpnClientCerts generates a client certificate for each client
// on an OpenVPN inbound that doesn't already have one on disk. If the
// OpenVPN server is running, it is reloaded so the new certs take effect.
// This is called from the inbound save and client-add paths.
func generateOpenvpnClientCerts(inbound *model.Inbound, clients []model.Client) error {
	if len(clients) == 0 {
		return nil
	}

	svc := NewOpenVPNService()
	if err := svc.InitPKI(); err != nil {
		return fmt.Errorf("openvpn: init pki: %w", err)
	}

	generated := 0
	for _, c := range clients {
		if c.Email == "" {
			continue
		}
		// Skip if cert already exists on disk.
		certPath := filepath.Join(openvpnBaseDir, clientsSubdir, c.Email+".crt")
		if _, statErr := os.Stat(certPath); statErr == nil {
			continue
		}
		if _, err := svc.GenerateClientCert(c.Email); err != nil {
			logger.Warning("openvpn: generate cert for", c.Email, ":", err)
			continue
		}
		generated++
	}

	if generated > 0 {
		logger.Infof("openvpn: generated %d client certificates for inbound %d", generated, inbound.Id)
		// If the server is running, reload it to pick up new certs.
		if svc.Status(inbound.Id) {
			if err := svc.Reload(inbound.Id); err != nil {
				logger.Warning("openvpn: reload after cert generation:", err)
			}
		}
	}
	return nil
}
