/*
 * Socket Sender
 * Modern ve kullanıcı dostu socket client uygulaması
 *
 * Yazılımcı: 02gur
 * GitHub: https://github.com/02gur/socketSender
 * Versiyon: 1.0.0
 * Lisans: MIT
 *
 * Özellikler:
 * - TCP, WebSocket (WS) ve WebSocket Secure (WSS) desteği
 * - CLI ve Web arayüzü
 * - Proxy desteği (HTTP, SOCKS5)
 * - Çoklu mesaj gönderme
 * - Header yönetimi
 * - Gerçek zamanlı mesajlaşma
 */

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

type SocketClient struct {
	conn        net.Conn
	wsConn      *websocket.Conn
	reader      *bufio.Reader
	writer      *bufio.Writer
	isWebSocket bool
	headers     map[string]string
	proxyURL    string
	mu          sync.RWMutex
	webClients  []*websocket.Conn
	webMu       sync.Mutex
}

func NewSocketClient() *SocketClient {
	return &SocketClient{
		headers: make(map[string]string),
	}
}

func (sc *SocketClient) Connect(address string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.conn != nil || sc.wsConn != nil {
		return fmt.Errorf("zaten bağlısınız")
	}

	// WebSocket URL kontrolü (ws:// veya wss://)
	if strings.HasPrefix(address, "ws://") || strings.HasPrefix(address, "wss://") {
		err := sc.connectWebSocket(address)
		if err == nil {
			message := fmt.Sprintf("✓ WebSocket bağlantı kuruldu: %s", address)
			fmt.Println(message)
			status := sc.getStatusUnlocked()
			sc.broadcastToWebClients(map[string]interface{}{
				"type":    "connected",
				"message": message,
				"status":  status,
			})
		} else {
			errorMsg := fmt.Sprintf("✗ Bağlantı hatası: %v", err)
			fmt.Println(errorMsg)
			sc.broadcastToWebClients(map[string]interface{}{
				"type":  "error",
				"error": errorMsg,
			})
		}
		return err
	}

	// Normal TCP bağlantısı
	var conn net.Conn
	var err error

	if sc.proxyURL != "" {
		// Proxy üzerinden bağlan
		proxyURL, parseErr := url.Parse(sc.proxyURL)
		if parseErr != nil {
			return fmt.Errorf("geçersiz proxy URL: %v", parseErr)
		}

		if proxyURL.Scheme == "socks5" {
			// SOCKS5 proxy
			auth := &proxy.Auth{}
			if proxyURL.User != nil {
				auth.User = proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				auth.Password = password
			}
			dialer, dialErr := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
			if dialErr != nil {
				return fmt.Errorf("SOCKS5 proxy hatası: %v", dialErr)
			}
			conn, err = dialer.Dial("tcp", address)
		} else if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
			// HTTP proxy - HTTP CONNECT method
			proxyConn, dialErr := net.Dial("tcp", proxyURL.Host)
			if dialErr != nil {
				return fmt.Errorf("proxy bağlantı hatası: %v", dialErr)
			}

			// HTTP CONNECT request
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)

			// Basic auth ekle
			if proxyURL.User != nil {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
				connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
			}

			connectReq += "\r\n"
			if _, writeErr := proxyConn.Write([]byte(connectReq)); writeErr != nil {
				proxyConn.Close()
				return fmt.Errorf("proxy request gönderme hatası: %v", writeErr)
			}

			// Response oku
			reader := bufio.NewReader(proxyConn)
			resp, readErr := http.ReadResponse(reader, nil)
			if readErr != nil {
				proxyConn.Close()
				return fmt.Errorf("proxy response okuma hatası: %v", readErr)
			}
			resp.Body.Close()

			if resp.StatusCode != 200 {
				proxyConn.Close()
				return fmt.Errorf("proxy bağlantı hatası: %s", resp.Status)
			}

			conn = proxyConn
		} else {
			return fmt.Errorf("desteklenmeyen proxy tipi: %s", proxyURL.Scheme)
		}
	} else {
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
	}

	if err != nil {
		errorMsg := fmt.Sprintf("✗ Bağlantı hatası: %v", err)
		fmt.Println(errorMsg)
		sc.broadcastToWebClients(map[string]interface{}{
			"type":  "error",
			"error": errorMsg,
		})
		return fmt.Errorf("bağlantı hatası: %v", err)
	}

	sc.conn = conn
	sc.reader = bufio.NewReader(conn)
	sc.writer = bufio.NewWriter(conn)
	sc.isWebSocket = false

	message := fmt.Sprintf("✓ TCP Bağlantı kuruldu: %s", address)
	fmt.Println(message)
	status := sc.getStatusUnlocked()
	sc.broadcastToWebClients(map[string]interface{}{
		"type":    "connected",
		"message": message,
		"status":  status,
	})
	return nil
}

func (sc *SocketClient) connectWebSocket(address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("geçersiz URL: %v", err)
	}

	// Proxy desteği
	var dialer websocket.Dialer
	if sc.proxyURL != "" {
		// Proxy kullan
		proxyURL, err := url.Parse(sc.proxyURL)
		if err != nil {
			return fmt.Errorf("geçersiz proxy URL: %v", err)
		}

		// Proxy için dialer oluştur
		var dialerFunc func(network, addr string) (net.Conn, error)
		if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
			// HTTP proxy - HTTP CONNECT method kullan
			dialerFunc = func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial("tcp", proxyURL.Host)
				if err != nil {
					return nil, fmt.Errorf("proxy bağlantı hatası: %v", err)
				}

				// HTTP CONNECT request
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)

				// Basic auth ekle
				if proxyURL.User != nil {
					username := proxyURL.User.Username()
					password, _ := proxyURL.User.Password()
					auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
					connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
				}

				connectReq += "\r\n"
				if _, err := conn.Write([]byte(connectReq)); err != nil {
					conn.Close()
					return nil, fmt.Errorf("proxy request gönderme hatası: %v", err)
				}

				// Response oku
				reader := bufio.NewReader(conn)
				resp, err := http.ReadResponse(reader, nil)
				if err != nil {
					conn.Close()
					return nil, fmt.Errorf("proxy response okuma hatası: %v", err)
				}
				resp.Body.Close()

				if resp.StatusCode != 200 {
					conn.Close()
					return nil, fmt.Errorf("proxy bağlantı hatası: %s", resp.Status)
				}

				return conn, nil
			}
		} else if proxyURL.Scheme == "socks5" {
			// SOCKS5 proxy
			auth := &proxy.Auth{}
			if proxyURL.User != nil {
				auth.User = proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				auth.Password = password
			}
			d, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
			if err != nil {
				return fmt.Errorf("SOCKS5 proxy hatası: %v", err)
			}
			dialerFunc = d.Dial
		} else {
			return fmt.Errorf("desteklenmeyen proxy tipi: %s", proxyURL.Scheme)
		}

		dialer = websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			NetDial:          dialerFunc,
		}
	} else {
		dialer = websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
		}
	}

	if u.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // Self-signed sertifikalar için
		}
	}

	// Header'ları hazırla
	requestHeaders := make(map[string][]string)

	// WebSocket handshake için otomatik eklenen header'lar (bunları kullanıcı eklememeli)
	// Connection, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Extensions
	// bunlar otomatik ekleniyor, kullanıcı header'larından filtrele
	websocketAutoHeaders := map[string]bool{
		"connection":               true,
		"upgrade":                  true,
		"sec-websocket-key":        true,
		"sec-websocket-version":    true,
		"sec-websocket-extensions": true,
		"sec-websocket-protocol":   false, // Bu kullanıcı tarafından eklenebilir
	}

	// Eğer Origin belirtilmemişse, URL'den otomatik oluştur
	if origin, ok := sc.headers["Origin"]; ok {
		requestHeaders["Origin"] = []string{origin}
	} else {
		// Otomatik Origin oluştur
		origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		requestHeaders["Origin"] = []string{origin}
	}

	// User-Agent ekle (belirtilmemişse)
	if userAgent, ok := sc.headers["User-Agent"]; ok {
		requestHeaders["User-Agent"] = []string{userAgent}
	} else {
		requestHeaders["User-Agent"] = []string{"Go-WebSocket-Client/1.0"}
	}

	// Kullanıcı tanımlı diğer header'ları ekle (case-insensitive kontrol)
	for key, value := range sc.headers {
		keyLower := strings.ToLower(key)

		// Otomatik eklenen header'ları atla
		if websocketAutoHeaders[keyLower] {
			continue
		}

		// Origin ve User-Agent zaten eklendi, tekrar ekleme
		if keyLower == "origin" || keyLower == "user-agent" {
			continue
		}

		// Header'ı ekle (HTTP header'ları case-insensitive ama Go'da canonical form kullanılır)
		requestHeaders[key] = []string{value}
	}

	// Path ve query parametrelerini ekle
	wsURL := u.String()
	if u.Path == "" {
		wsURL = strings.TrimSuffix(wsURL, "/") + "/"
	}

	// Debug: Gönderilen header'ları logla
	fmt.Println("📤 WebSocket handshake header'ları:")
	for key, values := range requestHeaders {
		for _, value := range values {
			// Uzun değerleri kısalt (Cookie gibi)
			displayValue := value
			if len(displayValue) > 100 {
				displayValue = displayValue[:100] + "..."
			}
			fmt.Printf("  %s: %s\n", key, displayValue)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeaders)
	if err != nil {
		if resp != nil {
			// Response header'larını da göster
			fmt.Println("📥 Sunucu yanıtı:")
			fmt.Printf("  Status: %d %s\n", resp.StatusCode, resp.Status)
			fmt.Println("  Response Header'ları:")
			for key, values := range resp.Header {
				for _, value := range values {
					fmt.Printf("    %s: %s\n", key, value)
				}
			}
			return fmt.Errorf("WebSocket bağlantı hatası: %v (Status: %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("WebSocket bağlantı hatası: %v", err)
	}

	sc.wsConn = conn
	sc.isWebSocket = true

	// Ping-pong mekanizmasını başlat (bağlantıyı canlı tutmak için)
	go sc.startPingPong()

	fmt.Printf("✓ WebSocket bağlantı kuruldu: %s\n", address)
	if len(sc.headers) > 0 {
		fmt.Println("  Kullanılan header'lar:")
		for key, value := range sc.headers {
			fmt.Printf("    %s: %s\n", key, value)
		}
	}
	return nil
}

// Ping-pong mekanizması - bağlantıyı canlı tutar
func (sc *SocketClient) startPingPong() {
	ticker := time.NewTicker(30 * time.Second) // Her 30 saniyede bir ping gönder
	defer ticker.Stop()

	failedPings := 0
	maxFailedPings := 3 // 3 kez başarısız olursa bağlantıyı kapat

	for range ticker.C {
		sc.mu.RLock()
		wsConn := sc.wsConn
		isWebSocket := sc.isWebSocket
		sc.mu.RUnlock()

		if !isWebSocket || wsConn == nil {
			return // Bağlantı kapandı, goroutine'i sonlandır
		}

		// Ping mesajı gönder (daha uzun timeout)
		err := wsConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second))
		if err != nil {
			failedPings++
			// Birkaç kez başarısız olursa bağlantıyı kapat
			if failedPings >= maxFailedPings {
				sc.mu.Lock()
				if sc.wsConn == wsConn {
					sc.wsConn = nil
					sc.isWebSocket = false
				}
				sc.mu.Unlock()
				fmt.Printf("⚠️  Ping %d kez başarısız oldu, bağlantı kapandı: %v\n", failedPings, err)
				sc.broadcastToWebClients(map[string]interface{}{
					"type":    "disconnected",
					"message": fmt.Sprintf("Bağlantı kapandı (ping %d kez başarısız)", failedPings),
					"status":  sc.GetStatus(),
				})
				return
			}
			// İlk başarısızlıklarda sadece uyarı ver
			fmt.Printf("⚠️  Ping başarısız (%d/%d): %v\n", failedPings, maxFailedPings, err)
		} else {
			// Ping başarılı, sayaç sıfırla
			if failedPings > 0 {
				failedPings = 0
				fmt.Println("✓ Ping başarılı, bağlantı canlı")
			}
		}
	}
}

func (sc *SocketClient) Send(data string) error {
	sc.mu.RLock()

	// Bağlantı kontrolü
	if sc.conn == nil && sc.wsConn == nil {
		sc.mu.RUnlock()
		return fmt.Errorf("bağlantı yok, önce 'connect <adres>' komutunu kullanın")
	}

	var wsConn *websocket.Conn
	var conn net.Conn
	var writer *bufio.Writer
	isWebSocket := sc.isWebSocket

	if sc.isWebSocket {
		wsConn = sc.wsConn
		if wsConn == nil {
			sc.mu.RUnlock()
			return fmt.Errorf("websocket bağlantısı yok")
		}
	} else {
		conn = sc.conn
		writer = sc.writer
		if conn == nil || writer == nil {
			sc.mu.RUnlock()
			return fmt.Errorf("tcp bağlantısı yok")
		}
	}
	sc.mu.RUnlock()

	// Lock'u bıraktıktan sonra yazma yap
	var err error
	if isWebSocket {
		// WebSocket için WriteDeadline ayarla (daha uzun timeout)
		wsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		err = wsConn.WriteMessage(websocket.TextMessage, []byte(data))
		if err != nil {
			// Bağlantı kopmuş olabilir, kontrol et
			sc.mu.Lock()
			// Bağlantı hala aynı mı kontrol et
			if sc.wsConn == wsConn {
				// Gerçekten kopmuş, temizle
				sc.wsConn = nil
				sc.isWebSocket = false
			}
			sc.mu.Unlock()
			return fmt.Errorf("gönderme hatası: %v", err)
		}
		// WriteDeadline'ı sıfırla (bağlantıyı açık tut)
		wsConn.SetWriteDeadline(time.Time{})
	} else {
		_, err = writer.WriteString(data + "\n")
		if err != nil {
			sc.mu.Lock()
			if sc.conn == conn {
				sc.conn = nil
				sc.reader = nil
				sc.writer = nil
			}
			sc.mu.Unlock()
			return fmt.Errorf("gönderme hatası: %v", err)
		}

		err = writer.Flush()
		if err != nil {
			sc.mu.Lock()
			if sc.conn == conn {
				sc.conn = nil
				sc.reader = nil
				sc.writer = nil
			}
			sc.mu.Unlock()
			return fmt.Errorf("flush hatası: %v", err)
		}
	}

	// Mesaj başarıyla gönderildi - sadece console'a yazdır
	// Web arayüzü zaten kendi mesajını gösteriyor
	fmt.Printf("✓ Veri gönderildi: %s\n", strings.TrimSpace(data))

	// Web client'lara gönder (sadece console'dan gönderildiyse)
	// Web arayüzünden gönderilen mesajlar zaten gösterildi
	sc.broadcastToWebClients(map[string]interface{}{
		"type":    "sent",
		"message": fmt.Sprintf("✓ Veri gönderildi: %s", strings.TrimSpace(data)),
		"data":    data,
	})
	return nil
}

func (sc *SocketClient) Receive() (string, error) {
	sc.mu.RLock()

	// Bağlantı kontrolü
	if sc.conn == nil && sc.wsConn == nil {
		sc.mu.RUnlock()
		return "", fmt.Errorf("bağlantı yok")
	}

	var message string
	var err error
	var isWebSocket bool
	var wsConn *websocket.Conn
	var conn net.Conn

	// Bağlantı referanslarını kopyala (lock süresini kısaltmak için)
	if sc.isWebSocket {
		wsConn = sc.wsConn
		isWebSocket = true
	} else {
		conn = sc.conn
		isWebSocket = false
	}
	sc.mu.RUnlock()

	// Lock'u bıraktıktan sonra okuma yap
	if isWebSocket {
		if wsConn == nil {
			return "", fmt.Errorf("websocket bağlantısı yok")
		}

		// Panic'i önlemek için recover kullan
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("websocket okuma panic: %v", r)
				// Bağlantıyı temizle
				sc.mu.Lock()
				if sc.wsConn == wsConn {
					sc.wsConn = nil
					sc.isWebSocket = false
				}
				sc.mu.Unlock()
			}
		}()

		// WebSocket bağlantısının durumunu kontrol et
		// Timeout'u artır (10 saniye) - bazı sunucular yavaş cevap verebilir
		wsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		msgType, msg, e := wsConn.ReadMessage()
		err = e

		// ReadDeadline'ı sıfırla (bağlantıyı açık tut)
		if err == nil {
			wsConn.SetReadDeadline(time.Time{})
		}
		if err == nil {
			// Sadece text mesajlarını işle
			if msgType == websocket.TextMessage {
				message = strings.TrimSpace(string(msg))
			} else if msgType == websocket.BinaryMessage {
				// Binary mesajları hex string olarak göster
				message = fmt.Sprintf("[Binary: %d bytes]", len(msg))
			} else if msgType == websocket.PingMessage {
				// Ping mesajı geldi, pong gönder
				wsConn.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(5*time.Second))
				return "", nil // Ping mesajını işleme, sadece pong gönder
			} else if msgType == websocket.PongMessage {
				// Pong mesajı geldi (normal, işleme gerek yok)
				return "", nil
			} else if msgType == websocket.CloseMessage {
				// Close mesajı geldi
				sc.mu.Lock()
				if sc.wsConn == wsConn {
					sc.wsConn = nil
					sc.isWebSocket = false
				}
				sc.mu.Unlock()
				return "", fmt.Errorf("websocket bağlantısı kapandı (close message)")
			} else {
				// Diğer mesaj tipleri
				message = fmt.Sprintf("[Message type: %d]", msgType)
			}
		} else {
			// WebSocket bağlantı hatalarını kontrol et
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				// Beklenmeyen kapanma - bağlantıyı temizle
				sc.mu.Lock()
				if sc.wsConn == wsConn {
					sc.wsConn = nil
					sc.isWebSocket = false
				}
				sc.mu.Unlock()
				return "", fmt.Errorf("websocket bağlantısı kapandı: %v", err)
			}
		}
	} else {
		if conn == nil {
			return "", fmt.Errorf("tcp bağlantısı yok")
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		sc.mu.RLock()
		reader := sc.reader
		sc.mu.RUnlock()

		if reader == nil {
			return "", fmt.Errorf("reader yok")
		}

		msg, e := reader.ReadString('\n')
		err = e
		if err == nil {
			message = strings.TrimSpace(msg)
		}
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout normal, veri yok demek - bağlantıyı kapatma
			return "", nil
		}
		// WebSocket timeout hatalarını kontrol et
		if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			sc.mu.Lock()
			if isWebSocket {
				sc.wsConn = nil
				sc.isWebSocket = false
			}
			sc.mu.Unlock()
			return "", fmt.Errorf("websocket bağlantısı kapandı")
		}
		// Bağlantı kapandı hatası
		if err.Error() == "EOF" || strings.Contains(err.Error(), "use of closed network connection") {
			sc.mu.Lock()
			if isWebSocket {
				sc.wsConn = nil
				sc.isWebSocket = false
			} else {
				sc.conn = nil
				sc.reader = nil
				sc.writer = nil
			}
			sc.mu.Unlock()
			return "", fmt.Errorf("bağlantı kapandı")
		}
		// Diğer hatalar için timeout kontrolü
		if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "timeout") {
			return "", nil // Timeout, veri yok demek
		}
		return "", err
	}

	if message != "" {
		// Gelen mesajı web client'lara gönder
		sc.broadcastToWebClients(map[string]interface{}{
			"type":    "received",
			"message": fmt.Sprintf("📥 Gelen veri: %s", message),
			"data":    message,
		})
		// Console'a da yazdır
		fmt.Printf("📥 Gelen veri: %s\n", message)
	}

	return message, nil
}

func (sc *SocketClient) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	var message string
	if sc.isWebSocket && sc.wsConn != nil {
		sc.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		sc.wsConn.Close()
		sc.wsConn = nil
		sc.isWebSocket = false
		message = "✓ WebSocket bağlantı kapatıldı"
	} else if sc.conn != nil {
		sc.conn.Close()
		sc.conn = nil
		sc.reader = nil
		sc.writer = nil
		message = "✓ TCP bağlantı kapatıldı"
	}

	if message != "" {
		fmt.Println(message)
		status := sc.getStatusUnlocked()
		sc.broadcastToWebClients(map[string]interface{}{
			"type":    "disconnected",
			"message": message,
			"status":  status,
		})
	}
}

func (sc *SocketClient) IsConnected() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.conn != nil || sc.wsConn != nil
}

func (sc *SocketClient) GetStatus() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.getStatusUnlocked()
}

func (sc *SocketClient) getStatusUnlocked() map[string]interface{} {
	connected := sc.conn != nil || sc.wsConn != nil
	status := map[string]interface{}{
		"connected": connected,
		"type":      "unknown",
		"address":   "",
		"headers":   make(map[string]string),
		"proxy":     sc.proxyURL,
	}

	// Headers'ı kopyala
	for k, v := range sc.headers {
		status["headers"].(map[string]string)[k] = v
	}

	if sc.isWebSocket && sc.wsConn != nil {
		status["type"] = "websocket"
		status["address"] = sc.wsConn.RemoteAddr().String()
	} else if sc.conn != nil {
		status["type"] = "tcp"
		status["address"] = sc.conn.RemoteAddr().String()
	}

	return status
}

func (sc *SocketClient) broadcastToWebClients(data map[string]interface{}) {
	sc.webMu.Lock()
	defer sc.webMu.Unlock()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	// Bağlantısı kopmuş client'ları temizle
	activeClients := []*websocket.Conn{}
	for _, client := range sc.webClients {
		err := client.WriteMessage(websocket.TextMessage, jsonData)
		if err != nil {
			client.Close()
			continue
		}
		activeClients = append(activeClients, client)
	}
	sc.webClients = activeClients
}

func (sc *SocketClient) addWebClient(conn *websocket.Conn) {
	sc.webMu.Lock()
	defer sc.webMu.Unlock()
	sc.webClients = append(sc.webClients, conn)
}

func (sc *SocketClient) removeWebClient(conn *websocket.Conn) {
	sc.webMu.Lock()
	defer sc.webMu.Unlock()
	for i, client := range sc.webClients {
		if client == conn {
			sc.webClients = append(sc.webClients[:i], sc.webClients[i+1:]...)
			break
		}
	}
}

func (sc *SocketClient) SetHeader(key, value string) {
	sc.mu.Lock()
	sc.headers[key] = value
	sc.mu.Unlock()

	message := fmt.Sprintf("✓ Header eklendi: %s: %s", key, value)
	fmt.Println(message)
	sc.broadcastToWebClients(map[string]interface{}{
		"type":    "info",
		"message": message,
		"status":  sc.GetStatus(),
	})
}

func (sc *SocketClient) SetProxy(proxyURL string) {
	sc.mu.Lock()
	sc.proxyURL = proxyURL
	sc.mu.Unlock()

	if proxyURL != "" {
		message := fmt.Sprintf("✓ Proxy ayarlandı: %s", proxyURL)
		fmt.Println(message)
	} else {
		fmt.Println("✓ Proxy kaldırıldı")
	}
	sc.broadcastToWebClients(map[string]interface{}{
		"type":    "info",
		"message": fmt.Sprintf("Proxy: %s", proxyURL),
		"status":  sc.GetStatus(),
	})
}

func (sc *SocketClient) GetProxy() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.proxyURL
}

func (sc *SocketClient) RemoveHeader(key string) {
	sc.mu.Lock()
	delete(sc.headers, key)
	sc.mu.Unlock()

	message := fmt.Sprintf("✓ Header kaldırıldı: %s", key)
	fmt.Println(message)
	sc.broadcastToWebClients(map[string]interface{}{
		"type":    "info",
		"message": message,
		"status":  sc.GetStatus(),
	})
}

func (sc *SocketClient) ListHeaders() {
	if len(sc.headers) == 0 {
		fmt.Println("📭 Tanımlı header yok")
		return
	}
	fmt.Println("📋 Tanımlı header'lar:")
	for key, value := range sc.headers {
		fmt.Printf("  %s: %s\n", key, value)
	}
}

func (sc *SocketClient) ClearHeaders() {
	sc.headers = make(map[string]string)
	fmt.Println("✓ Tüm header'lar temizlendi")
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Tüm origin'lere izin ver
	},
}

func getWebInterface() string {
	return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Socket Client - Web Arayüzü</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .status {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }
        .status.connected {
            background: #4caf50;
        }
        .status.disconnected {
            background: #f44336;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 10px;
        }
        .section h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 600;
        }
        input, textarea, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-right: 10px;
            margin-top: 10px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        button.danger {
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);
        }
        button.success {
            background: linear-gradient(135deg, #4caf50 0%, #388e3c 100%);
        }
        .messages {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .message {
            margin-bottom: 10px;
            padding: 8px;
            border-radius: 4px;
        }
        .message.sent {
            background: rgba(76, 175, 80, 0.2);
            border-left: 3px solid #4caf50;
        }
        .message.received {
            background: rgba(33, 150, 243, 0.2);
            border-left: 3px solid #2196f3;
        }
        .message.error {
            background: rgba(244, 67, 54, 0.2);
            border-left: 3px solid #f44336;
        }
        .message.info {
            background: rgba(255, 193, 7, 0.2);
            border-left: 3px solid #ffc107;
        }
        .headers-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        .header-item {
            background: white;
            padding: 10px 15px;
            border-radius: 8px;
            border: 2px solid #ddd;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-item strong {
            color: #667eea;
        }
        .header-item button {
            padding: 5px 10px;
            margin: 0;
            font-size: 12px;
        }
        .row {
            display: flex;
            gap: 15px;
        }
        .row .form-group {
            flex: 1;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .messages {
            scroll-behavior: smooth;
        }
        .message {
            word-wrap: break-word;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔌 Socket Client</h1>
            <div class="status disconnected" id="status">Bağlı Değil</div>
        </div>
        <div class="content">
            <div class="section">
                <h2>Mesaj Geçmişi</h2>
                <div style="margin-bottom: 10px;">
                    <button onclick="clearMessages()" style="font-size: 12px; padding: 6px 12px;">Mesaj Geçmişini Temizle</button>
                    <button onclick="scrollToBottom()" style="font-size: 12px; padding: 6px 12px;">En Alta Kaydır</button>
                </div>
                <div class="messages" id="messages"></div>
            </div>

            <div class="section">
                <h2>Bağlantı</h2>
                <div class="form-group">
                    <label>Proxy (Opsiyonel - Charles için: http://localhost:8888)</label>
                    <input type="text" id="proxyURL" placeholder="http://localhost:8888 veya socks5://127.0.0.1:1080">
                </div>
                <button onclick="setProxy()">Proxy Ayarla</button>
                <button onclick="removeProxy()">Proxy Kaldır</button>
                <div id="proxyStatus" style="margin-top: 10px; color: #666; font-size: 0.9em;"></div>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
                <div class="form-group">
                    <label>Socket Adresi</label>
                    <input type="text" id="address" placeholder="wss://api.example.com/v2 veya localhost:8080">
                </div>
                <button class="success" onclick="connect()">Bağlan</button>
                <button class="danger" onclick="disconnect()">Bağlantıyı Kes</button>
            </div>

            <div class="section">
                <h2>Mesaj Gönder</h2>
                <div class="form-group">
                    <label>Mesaj (Her satır ayrı bir mesaj olarak gönderilir)</label>
                    <textarea id="message" rows="8" placeholder="Göndermek istediğiniz mesajı yazın...&#10;Birden fazla mesaj için her satıra bir mesaj yazın:&#10;[1,\"test\"]&#10;[2,\"test2\"]&#10;[3,\"test3\"]"></textarea>
                    <small style="color: #666; display: block; margin-top: 5px;">
                        Birden fazla mesaj göndermek için her satıra bir mesaj yazın. Boş satırlar atlanır.
                    </small>
                </div>
                <button onclick="sendMessage()">Gönder</button>
            </div>

            <div class="section">
                <h2>Header Yönetimi</h2>
                <div class="form-group">
                    <label>Raw Header'lar (Alt Alta Yapıştırın)</label>
                    <textarea id="rawHeaders" rows="8" placeholder="Origin: https://example.com&#10;Cookie: session=abc123...&#10;Authorization: Bearer token...&#10;Sec-WebSocket-Protocol: wamp.2.json"></textarea>
                    <small style="color: #666; display: block; margin-top: 5px;">
                        Header'ları "Key: Value" formatında alt alta yapıştırın<br>
                        <strong>Not:</strong> Connection, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version header'ları otomatik eklenir, eklemeyin!
                    </small>
                </div>
                <button onclick="parseAndAddHeaders()">Header'ları Parse Et ve Ekle</button>
                <button onclick="clearAllHeaders()">Tüm Header'ları Temizle</button>
                <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
                <div class="row">
                    <div class="form-group">
                        <label>Header Key</label>
                        <input type="text" id="headerKey" placeholder="Örn: Origin, Authorization">
                    </div>
                    <div class="form-group">
                        <label>Header Value</label>
                        <input type="text" id="headerValue" placeholder="Örn: https://example.com">
                    </div>
                </div>
                <button onclick="addHeader()">Tek Header Ekle</button>
                <div class="headers-list" id="headersList"></div>
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let currentStatus = { connected: false };

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');

            ws.onopen = () => {
                addMessage('Web arayüzü bağlandı', 'info');
                ws.send(JSON.stringify({ action: 'getStatus' }));
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'status') {
                    updateStatus(data.status);
                } else if (data.type === 'connected') {
                    addMessage(data.message, 'info');
                    if (data.status) updateStatus(data.status);
                } else if (data.type === 'disconnected') {
                    addMessage(data.message, 'info');
                    if (data.status) updateStatus(data.status);
                } else if (data.type === 'sent') {
                    // Console'dan gönderilen mesajlar için backend'den gelen mesajı göster
                    // Web arayüzünden gönderilen mesajlar zaten sendMessage()'da gösterildi
                    // Duplicate önlemek için kontrol et
                    if (lastSentMessage !== data.data) {
                        addMessage('sender: ' + data.data, 'sent');
                    }
                    lastSentMessage = null; // Reset
                } else if (data.type === 'received') {
                    // Gelen mesajları her zaman göster
                    addMessage('receiver: ' + data.data, 'received');
                } else if (data.type === 'success') {
                    addMessage(data.message, 'info');
                    if (data.status) updateStatus(data.status);
                } else if (data.type === 'error') {
                    addMessage('Hata: ' + (data.error || data.message), 'error');
                    if (data.status) updateStatus(data.status);
                } else if (data.type === 'info') {
                    addMessage(data.message, 'info');
                    if (data.status) updateStatus(data.status);
                }
            };

            ws.onerror = (error) => {
                addMessage('WebSocket hatası', 'error');
            };

            ws.onclose = () => {
                addMessage('Web arayüzü bağlantısı kesildi', 'error');
                setTimeout(connectWebSocket, 3000);
            };
        }

        function updateStatus(status) {
            currentStatus = status;
            const statusEl = document.getElementById('status');
            if (status.connected) {
                statusEl.textContent = 'Bağlı: ' + status.address;
                statusEl.className = 'status connected';
            } else {
                statusEl.textContent = 'Bağlı Değil';
                statusEl.className = 'status disconnected';
            }
            updateHeadersList(status.headers || {});
            
            // Proxy durumunu göster
            const proxyStatus = document.getElementById('proxyStatus');
            if (status.proxy && status.proxy !== '') {
                proxyStatus.textContent = '🔗 Proxy: ' + status.proxy;
                proxyStatus.style.color = '#4caf50';
            } else {
                proxyStatus.textContent = '🔗 Proxy: Kapalı';
                proxyStatus.style.color = '#999';
            }
        }

        function connect() {
            const address = document.getElementById('address').value;
            if (!address) {
                addMessage('Lütfen bir adres girin', 'error');
                return;
            }
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                addMessage('Web arayüzü bağlantısı yok, bekleniyor...', 'error');
                return;
            }
            addMessage('Bağlanılıyor: ' + address, 'info');
            ws.send(JSON.stringify({ action: 'connect', address: address }));
        }

        function disconnect() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: 'disconnect' }));
            }
        }

        function setProxy() {
            const proxyURL = document.getElementById('proxyURL').value.trim();
            if (!proxyURL) {
                addMessage('Lütfen bir proxy URL girin', 'error');
                return;
            }
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: 'setProxy', proxyURL: proxyURL }));
            } else {
                addMessage('Web arayüzü bağlantısı yok', 'error');
            }
        }

        function removeProxy() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: 'setProxy', proxyURL: '' }));
                document.getElementById('proxyURL').value = '';
            } else {
                addMessage('Web arayüzü bağlantısı yok', 'error');
            }
        }

        let lastSentMessage = null;
        let isSendingMultiple = false;
        
        async function sendMessage() {
            const messageText = document.getElementById('message').value;
            if (!messageText || !messageText.trim()) {
                addMessage('Lütfen bir mesaj girin', 'error');
                return;
            }
            if (ws && ws.readyState !== WebSocket.OPEN) {
                addMessage('Bağlantı yok', 'error');
                return;
            }
            
            // Her satırı ayrı bir mesaj olarak işle
            const lines = messageText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            
            if (lines.length === 0) {
                addMessage('Geçerli mesaj bulunamadı', 'error');
                return;
            }
            
            if (lines.length === 1) {
                // Tek mesaj
                const msg = lines[0];
                addMessage('sender: ' + msg, 'sent');
                lastSentMessage = msg;
                ws.send(JSON.stringify({ action: 'send', data: msg }));
                document.getElementById('message').value = '';
            } else {
                // Çoklu mesaj
                isSendingMultiple = true;
                addMessage('📤 ' + lines.length + ' mesaj sırasıyla gönderiliyor...', 'info');
                
                for (let i = 0; i < lines.length; i++) {
                    const msg = lines[i];
                    addMessage('📤 Mesaj ' + (i+1) + '/' + lines.length + ': sender: ' + msg, 'sent');
                    lastSentMessage = msg;
                    
                    // Mesajı gönder
                    ws.send(JSON.stringify({ action: 'send', data: msg }));
                    
                    // Mesajlar arasında kısa bir bekleme (sunucuya yük bindirmemek için)
                    if (i < lines.length - 1) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                }
                
                document.getElementById('message').value = '';
                isSendingMultiple = false;
                addMessage('✓ ' + lines.length + ' mesaj gönderildi', 'info');
            }
            
            // Mesaj alanına odaklan (hızlı mesaj göndermek için)
            document.getElementById('message').focus();
        }
        
        // Enter tuşu ile mesaj gönderme
        document.addEventListener('DOMContentLoaded', function() {
            const messageInput = document.getElementById('message');
            if (messageInput) {
                messageInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendMessage();
                    }
                });
            }
        });

        function parseAndAddHeaders() {
            const rawText = document.getElementById('rawHeaders').value.trim();
            if (!rawText) {
                addMessage('Lütfen header\'ları girin', 'error');
                return;
            }
            
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                addMessage('Web arayüzü bağlantısı yok', 'error');
                return;
            }

            // Otomatik eklenen header'lar (bunları eklememeli)
            const autoHeaders = {
                'connection': true,
                'upgrade': true,
                'sec-websocket-key': true,
                'sec-websocket-version': true,
                'sec-websocket-extensions': true
            };

            const lines = rawText.split('\n');
            let added = 0;
            let skipped = 0;
            let autoSkipped = 0;

            for (let line of lines) {
                line = line.trim();
                if (!line) continue;

                // "Key: Value" formatını parse et
                const colonIndex = line.indexOf(':');
                if (colonIndex === -1) {
                    skipped++;
                    continue;
                }

                const key = line.substring(0, colonIndex).trim();
                const value = line.substring(colonIndex + 1).trim();

                if (!key || !value) {
                    skipped++;
                    continue;
                }

                // Otomatik eklenen header'ları kontrol et
                const keyLower = key.toLowerCase();
                if (autoHeaders[keyLower]) {
                    autoSkipped++;
                    addMessage('Uyarı: ' + key + ' header\'ı otomatik eklenir, atlandı', 'info');
                    continue;
                }

                // Header'ı ekle
                ws.send(JSON.stringify({ action: 'setHeader', key: key, value: value }));
                added++;
            }

            if (added > 0) {
                var msg = added + ' header eklendi';
                if (skipped > 0) {
                    msg += ' (' + skipped + ' geçersiz satır atlandı)';
                }
                if (autoSkipped > 0) {
                    msg += ' (' + autoSkipped + ' otomatik header atlandı)';
                }
                addMessage(msg, 'info');
                document.getElementById('rawHeaders').value = '';
            } else {
                addMessage('Geçerli header bulunamadı', 'error');
            }
        }

        function clearAllHeaders() {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                addMessage('Web arayüzü bağlantısı yok', 'error');
                return;
            }
            
            if (confirm('Tüm header\'ları temizlemek istediğinize emin misiniz?')) {
                ws.send(JSON.stringify({ action: 'clearHeaders' }));
            }
        }

        function addHeader() {
            const key = document.getElementById('headerKey').value;
            const value = document.getElementById('headerValue').value;
            if (!key || !value) {
                addMessage('Lütfen key ve value girin', 'error');
                return;
            }
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: 'setHeader', key: key, value: value }));
                document.getElementById('headerKey').value = '';
                document.getElementById('headerValue').value = '';
            }
        }

        function removeHeader(key) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: 'removeHeader', key: key }));
            }
        }

        function updateHeadersList(headers) {
            const list = document.getElementById('headersList');
            list.innerHTML = '';
            for (const [key, value] of Object.entries(headers)) {
                const item = document.createElement('div');
                item.className = 'header-item';
                item.innerHTML = '<strong>' + key + ':</strong> ' + value + 
                    ' <button class="danger" onclick="removeHeader(\'' + key + '\')">Kaldır</button>';
                list.appendChild(item);
            }
        }

        function addMessage(text, type) {
            const messages = document.getElementById('messages');
            const message = document.createElement('div');
            message.className = 'message ' + type;
            const time = new Date().toLocaleTimeString();
            message.textContent = '[' + time + '] ' + text;
            messages.appendChild(message);
            
            // Otomatik scroll - her zaman en alta kaydır (smooth)
            scrollToBottom();
            
            // Yeni mesaj geldiğinde görsel geri bildirim
            message.style.animation = 'fadeIn 0.3s';
        }
        
        function scrollToBottom() {
            const messages = document.getElementById('messages');
            messages.scrollTop = messages.scrollHeight;
        }
        
        function clearMessages() {
            if (confirm('Mesaj geçmişini temizlemek istediğinize emin misiniz?')) {
                document.getElementById('messages').innerHTML = '';
            }
        }
        
        // Mesaj alanına Enter tuşu ile mesaj gönderme
        document.addEventListener('DOMContentLoaded', function() {
            const messageInput = document.getElementById('message');
            if (messageInput) {
                messageInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendMessage();
                    }
                });
            }
            
            // Sayfa yüklendiğinde mesaj alanına odaklan
            messageInput.focus();
        });

        connectWebSocket();
    </script>
</body>
</html>`
}

func setupWebServer(client *SocketClient) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, getWebInterface())
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade hatası: %v", err)
			return
		}
		defer conn.Close()

		client.addWebClient(conn)
		defer client.removeWebClient(conn)

		// İlk bağlantıda mevcut durumu gönder
		status := client.GetStatus()
		conn.WriteJSON(map[string]interface{}{
			"type":   "status",
			"status": status,
		})

		for {
			var msg map[string]interface{}
			err := conn.ReadJSON(&msg)
			if err != nil {
				break
			}

			action := msg["action"].(string)
			switch action {
			case "connect":
				address := msg["address"].(string)
				// Bağlantı başladı mesajı gönder
				conn.WriteJSON(map[string]interface{}{
					"type":    "info",
					"message": fmt.Sprintf("🔄 Bağlanılıyor: %s", address),
				})
				err := client.Connect(address)
				if err != nil {
					conn.WriteJSON(map[string]interface{}{
						"type":    "error",
						"error":   fmt.Sprintf("✗ Bağlantı başarısız: %v", err),
						"message": fmt.Sprintf("✗ Bağlantı başarısız: %v", err),
						"status":  client.GetStatus(),
					})
				} else {
					conn.WriteJSON(map[string]interface{}{
						"type":    "connected",
						"message": fmt.Sprintf("✓ Bağlantı başarılı: %s", address),
						"status":  client.GetStatus(),
					})
				}

			case "send":
				data := msg["data"].(string)
				err := client.Send(data)
				if err != nil {
					conn.WriteJSON(map[string]interface{}{
						"type":   "error",
						"error":  err.Error(),
						"status": client.GetStatus(),
					})
				} else {
					// Başarılı gönderim sonrası durumu güncelle
					conn.WriteJSON(map[string]interface{}{
						"type":   "status",
						"status": client.GetStatus(),
					})
				}

			case "disconnect":
				client.Close()
				conn.WriteJSON(map[string]interface{}{
					"type":    "success",
					"message": "Bağlantı kapatıldı",
					"status":  client.GetStatus(),
				})

			case "setHeader":
				key := msg["key"].(string)
				value := msg["value"].(string)
				client.SetHeader(key, value)
				conn.WriteJSON(map[string]interface{}{
					"type":    "success",
					"message": "Header eklendi",
					"status":  client.GetStatus(),
				})

			case "removeHeader":
				key := msg["key"].(string)
				client.RemoveHeader(key)
				conn.WriteJSON(map[string]interface{}{
					"type":    "success",
					"message": "Header kaldırıldı",
					"status":  client.GetStatus(),
				})

			case "clearHeaders":
				client.ClearHeaders()
				conn.WriteJSON(map[string]interface{}{
					"type":    "success",
					"message": "Tüm header'lar temizlendi",
					"status":  client.GetStatus(),
				})

			case "setProxy":
				proxyURL := msg["proxyURL"].(string)
				client.SetProxy(proxyURL)
				conn.WriteJSON(map[string]interface{}{
					"type":    "success",
					"message": fmt.Sprintf("Proxy ayarlandı: %s", proxyURL),
					"status":  client.GetStatus(),
				})

			case "getStatus":
				conn.WriteJSON(map[string]interface{}{
					"type":   "status",
					"status": client.GetStatus(),
				})
			}
		}
	})

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client.GetStatus())
	})

	fmt.Println("🌐 Web arayüzü: http://localhost:8080")
	fmt.Println("🌐 02gur [github.com/02gur]")
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Printf("Web sunucu hatası: %v", err)
		}
	}()
}

func printHelp() {
	fmt.Println("\nKullanılabilir Komutlar:")
	fmt.Println("  connect <adres>       - Socket sunucusuna bağlan")
	fmt.Println("                        - TCP: connect localhost:8080")
	fmt.Println("                        - WS:  connect ws://localhost:8080/ws")
	fmt.Println("                        - WSS: connect wss://example.com/ws")
	fmt.Println("  header <key> <value>  - WebSocket için header ekle")
	fmt.Println("                        - Örnek: header Origin https://example.com")
	fmt.Println("                        - Örnek: header Authorization Bearer token123")
	fmt.Println("  remove-header <key>   - Header kaldır")
	fmt.Println("  list-headers          - Tanımlı header'ları listele")
	fmt.Println("  clear-headers         - Tüm header'ları temizle")
	fmt.Println("  send <veri>           - Veri gönder")
	fmt.Println("  receive               - Gelen veriyi oku (non-blocking)")
	fmt.Println("  disconnect            - Bağlantıyı kapat")
	fmt.Println("  status                - Bağlantı durumunu göster")
	fmt.Println("  proxy <url>           - Proxy ayarla (örn: proxy http://localhost:8888)")
	fmt.Println("                        - Charles için: proxy http://localhost:8888")
	fmt.Println("  proxy-off             - Proxy'yi kapat")
	fmt.Println("  help                  - Bu yardım mesajını göster")
	fmt.Println("  exit                  - Programdan çık")
	fmt.Println()
}

func main() {
	client := NewSocketClient()

	// Web sunucusunu başlat
	setupWebServer(client)

	// Readline oluştur (komut geçmişi ve ok tuşları için)
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "socket> ",
		HistoryFile:       "/tmp/socketSender_history",
		AutoComplete:      nil,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		fmt.Printf("Readline hatası: %v\n", err)
		return
	}
	defer rl.Close()

	fmt.Println("=== Socket Client ===")
	fmt.Println("'help' yazarak komutları görebilirsiniz")
	fmt.Println("Ok tuşları ile komut geçmişinde gezinebilirsiniz")
	fmt.Println("🌐 Web arayüzü: http://localhost:8080")
	fmt.Println("🌐 02gur [github.com/02gur]")
	fmt.Println()
	printHelp()

	// Arka planda veri dinleme
	go func() {
		for {
			if client.IsConnected() {
				message, err := client.Receive()
				if err != nil {
					// Bağlantı kapandı hatası ise sadece bir kez logla
					if strings.Contains(err.Error(), "bağlantı kapandı") ||
						strings.Contains(err.Error(), "websocket bağlantısı kapandı") {
						fmt.Printf("⚠️  Bağlantı kapandı: %v\n", err)
						// Bağlantı durumunu güncelle
						client.broadcastToWebClients(map[string]interface{}{
							"type":    "disconnected",
							"message": "Bağlantı kapandı",
							"status":  client.GetStatus(),
						})
						// Bağlantı kapandıysa biraz daha uzun bekle
						time.Sleep(1 * time.Second)
					} else if !strings.Contains(err.Error(), "bağlantı yok") &&
						!strings.Contains(err.Error(), "timeout") &&
						!strings.Contains(err.Error(), "i/o timeout") {
						// Sadece gerçek hataları göster
						if client.IsConnected() {
							fmt.Printf("✗ Okuma hatası: %v\n", err)
						}
						// Hata durumunda kısa bir süre bekle
						time.Sleep(500 * time.Millisecond)
					}
					// Timeout hataları normal, devam et
					continue
				}
				// Mesaj alındı (zaten Receive() içinde console'a ve web client'lara gönderildi)
				if message != "" {
					// Mesaj zaten gösterildi, sadece kısa bir bekleme
					time.Sleep(10 * time.Millisecond)
				}
			}
			// Bağlantı yoksa daha uzun bekle
			if !client.IsConnected() {
				time.Sleep(500 * time.Millisecond)
			} else {
				// Bağlantı varsa daha sık kontrol et (daha hızlı yanıt için)
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if client.IsConnected() {
					client.Close()
				}
				fmt.Println("\nÇıkılıyor...")
				return
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := strings.ToLower(parts[0])

		switch command {
		case "connect":
			if len(parts) < 2 {
				fmt.Println("✗ Kullanım: connect <adres:port>")
				continue
			}
			if client.IsConnected() {
				fmt.Println("✗ Zaten bağlısınız. Önce 'disconnect' yapın.")
				continue
			}
			address := parts[1]
			fmt.Printf("🔄 Bağlanılıyor: %s\n", address)
			if err := client.Connect(address); err != nil {
				fmt.Printf("✗ Bağlantı başarısız: %v\n", err)
			} else {
				fmt.Printf("✓ Bağlantı başarılı: %s\n", address)
			}

		case "header":
			if len(parts) < 3 {
				fmt.Println("✗ Kullanım: header <key> <value>")
				fmt.Println("  Örnek: header Origin https://example.com")
				continue
			}
			key := parts[1]
			value := strings.Join(parts[2:], " ")
			client.SetHeader(key, value)

		case "remove-header":
			if len(parts) < 2 {
				fmt.Println("✗ Kullanım: remove-header <key>")
				continue
			}
			client.RemoveHeader(parts[1])

		case "list-headers":
			client.ListHeaders()

		case "clear-headers":
			client.ClearHeaders()

		case "send":
			if len(parts) < 2 {
				fmt.Println("✗ Kullanım: send <veri>")
				fmt.Println("  Çoklu mesaj için: send <mesaj1> || <mesaj2> || <mesaj3>")
				fmt.Println("  Örnek: send [1,\"test\"] || [2,\"test2\"]")
				continue
			}
			data := strings.Join(parts[1:], " ")

			// Çoklu mesaj kontrolü (|| ile ayrılmış)
			if strings.Contains(data, " || ") {
				messages := strings.Split(data, " || ")
				for i, msg := range messages {
					msg = strings.TrimSpace(msg)
					if msg == "" {
						continue
					}
					fmt.Printf("📤 Mesaj %d/%d gönderiliyor...\n", i+1, len(messages))
					if err := client.Send(msg); err != nil {
						fmt.Printf("✗ Mesaj %d gönderme hatası: %v\n", i+1, err)
						break // Hata olursa dur
					}
					// Mesajlar arasında kısa bir bekleme (sunucuya yük bindirmemek için)
					if i < len(messages)-1 {
						time.Sleep(100 * time.Millisecond)
					}
				}
			} else {
				if err := client.Send(data); err != nil {
					fmt.Printf("✗ %v\n", err)
				}
			}

		case "receive":
			if !client.IsConnected() {
				fmt.Println("✗ Bağlantı yok")
				continue
			}
			message, err := client.Receive()
			if err != nil {
				fmt.Printf("✗ %v\n", err)
			} else if message != "" {
				fmt.Printf("📥 Gelen veri: %s\n", message)
			} else {
				fmt.Println("📭 Gelen veri yok")
			}

		case "disconnect":
			if !client.IsConnected() {
				fmt.Println("✗ Zaten bağlı değilsiniz")
				continue
			}
			client.Close()

		case "status":
			if client.IsConnected() {
				if client.isWebSocket && client.wsConn != nil {
					fmt.Printf("✓ WebSocket bağlı: %s\n", client.wsConn.RemoteAddr().String())
				} else if client.conn != nil {
					fmt.Printf("✓ TCP bağlı: %s\n", client.conn.RemoteAddr().String())
				}
			} else {
				fmt.Println("✗ Bağlı değil")
			}
			if proxy := client.GetProxy(); proxy != "" {
				fmt.Printf("🔗 Proxy: %s\n", proxy)
			}

		case "proxy":
			if len(parts) < 2 {
				fmt.Println("✗ Kullanım: proxy <url>")
				fmt.Println("  Örnek: proxy http://localhost:8888")
				fmt.Println("  Örnek: proxy socks5://127.0.0.1:1080")
				continue
			}
			proxyURL := parts[1]
			client.SetProxy(proxyURL)

		case "proxy-off":
			client.SetProxy("")

		case "help":
			printHelp()

		case "exit", "quit":
			if client.IsConnected() {
				client.Close()
			}
			fmt.Println("Çıkılıyor...")
			return

		default:
			fmt.Printf("✗ Bilinmeyen komut: %s (yardım için 'help' yazın)\n", command)
		}
	}
}
