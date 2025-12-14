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
    <title>Socket Sender Pro</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #f8fafc;
            --bg-card: #ffffff;
            --bg-input: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #64748b;
            --accent-primary: #6366f1;
            --accent-hover: #4f46e5;
            --accent-secondary: #0ea5e9;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --border: #e2e8f0;
            --glass: rgba(255, 255, 255, 0.9);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: var(--bg-dark); 
        }
        ::-webkit-scrollbar-thumb {
            background: var(--bg-input); 
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary); 
        }

        /* Layout */
        .app-container {
            display: flex;
            height: 100vh;
            max-width: 1600px;
            margin: 0 auto;
            width: 100%;
            background: var(--bg-dark);
            box-shadow: 0 0 50px rgba(0,0,0,0.5);
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: var(--bg-card);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            padding: 20px;
            z-index: 10;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 10px;
            letter-spacing: -0.5px;
        }
        .logo span {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-menu {
            display: flex;
            flex-direction: column;
            gap: 5px;
            flex: 1;
        }

        .nav-item {
            padding: 12px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            color: var(--text-secondary);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .nav-item:hover {
            background: rgba(255,255,255,0.05);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: linear-gradient(90deg, rgba(99, 102, 241, 0.1), transparent);
            color: var(--accent-primary);
            border-left: 3px solid var(--accent-primary);
        }

        .connection-status {
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
            margin-top: auto;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
            margin-bottom: 5px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-secondary);
            box-shadow: 0 0 10px rgba(0,0,0,0.2);
            transition: background 0.3s;
        }
        .status-dot.connected { background: var(--success); box-shadow: 0 0 10px var(--success); }
        .status-dot.disconnected { background: var(--danger); box-shadow: 0 0 10px var(--danger); }

        .status-text {
            color: var(--text-secondary);
            font-size: 0.8rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            position: relative;
        }

        .tab-content {
            display: none;
            height: 100%;
            flex-direction: column;
        }
        .tab-content.active {
            display: flex;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Header Bar */
        .top-bar {
            height: 60px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            padding: 0 20px;
            justify-content: space-between;
            background: var(--glass);
            backdrop-filter: blur(10px);
        }

        .page-title {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .proxy-badge {
            font-size: 0.75rem;
            padding: 4px 8px;
            border-radius: 4px;
            background: var(--bg-input);
            color: var(--text-secondary);
            display: none;
            align-items: center;
            gap: 5px;
        }
        .proxy-badge.active { display: flex; }
        .proxy-badge.active span { color: var(--success); }

        /* Forms & Inputs */
        .input-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }

        input[type="text"], textarea {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid transparent;
            color: var(--text-primary);
            padding: 12px 16px;
            border-radius: 8px;
            font-family: 'Inter', sans-serif;
            font-size: 0.95rem;
            transition: all 0.2s;
        }
        textarea {
            font-family: 'JetBrains Mono', monospace;
            resize: vertical;
        }

        input:focus, textarea:focus {
            outline: none;
            border-color: var(--accent-primary);
            background: rgba(99, 102, 241, 0.05);
        }

        button {
            background: var(--accent-primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 0.95rem;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        button:hover {
            background: var(--accent-hover);
            transform: translateY(-1px);
        }
        button:active {
            transform: translateY(0);
        }

        button.secondary { background: var(--bg-input); color: var(--text-primary); }
        button.secondary:hover { background: #475569; }

        button.danger { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
        button.danger:hover { background: rgba(239, 68, 68, 0.2); }

        /* Connection Bar (in Message Tab) */
        .connection-bar {
            padding: 20px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            display: flex;
            gap: 30px;
        }
        .url-input-container {
            flex: 1;
            display: flex;
            gap: 10px;
        }

        /* Message Area */
        .message-history {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            background: #0b1120;
        }

        .message-item {
            width: 100%;
            padding: 8px 12px;
            border-radius: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            position: relative;
            word-break: break-all;
            animation: slideIn 0.2s ease;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-item.sent {
            align-self: flex-start;
            background: rgba(99, 102, 241, 0.1); /* Light indigo bg for sent */
            color: var(--text-primary);
            border-left: 3px solid var(--accent-primary);
            border-bottom-right-radius: 12px;
        }

        .message-item.received {
            align-self: flex-start;
            background: transparent;
            color: #0fef37;
            border-left: 3px solid var(--success);
            border-bottom-left-radius: 12px;
        }

        .message-item.info {
            align-self: flex-start;
            background: transparent;
            color: var(--text-secondary);
            font-size: 0.8rem;
            padding: 4px 12px;
            border-left: 3px solid var(--text-secondary);
        }

        .message-item.error {
            align-self: flex-start;
            background: rgba(239, 68, 68, 0.05);
            color: var(--danger);
            border: none;
            border-left: 3px solid var(--danger);
            text-align: left;
        }

        .message-meta {
            font-size: 0.7rem;
            opacity: 0.7;
            margin-bottom: 4px;
            display: block;
        }

        .message-input-area {
            padding: 20px;
            background: var(--bg-card);
            border-top: 1px solid var(--border);
        }

        /* Proxy & Headers Pages */
        .page-content {
            padding: 30px;
            max-width: 800px;
        }

        .card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 30px;
            border: 1px solid var(--border);
        }

        .header-list {
            margin-top: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .header-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-dark);
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .header-key { color: var(--accent-secondary); font-weight: 500; }
        .header-val { color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; }

        .helper-text {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-top: 8px;
            line-height: 1.5;
        }

    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <span>⚡</span> SocketPro
            </div>
            
            <div class="nav-menu">
                <div class="nav-item active" onclick="switchTab('tab-messages')">
                    <span>💬</span> Mesajlaşma
                </div>
                <div class="nav-item" onclick="switchTab('tab-proxy')">
                    <span>🛡️</span> Proxy Ayarları
                </div>
                <div class="nav-item" onclick="switchTab('tab-headers')">
                    <span>📑</span> Header Yönetimi
                </div>
            </div>

            <div class="connection-status">
                <div class="status-indicator">
                    <div id="statusDot" class="status-dot disconnected"></div>
                    <span id="statusText" style="font-weight: 600;">Bağlı Değil</span>
                </div>
                <div id="statusAddress" class="status-text">-</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            
            <!-- Global Top Bar -->
            <div class="top-bar">
                <div class="page-title" id="pageTitle">Mesajlaşma</div>
                <div class="proxy-badge" id="proxyBadge">
                    <span>●</span> Proxy Aktif
                </div>
            </div>

            <!-- Tab 1: Messages -->
            <div id="tab-messages" class="tab-content active">
                <div class="connection-bar">
                    <div class="url-input-container">
                        <input type="text" id="address" placeholder="ws://localhost:8080 veya wss://api.example.com" value="ws://localhost:8080">
                        <button onclick="connect()" id="btnConnect">Bağlan</button>
                        <button onclick="disconnect()" class="danger" id="btnDisconnect" style="display:none;">Kes</button>
                    </div>
                </div>

                <div class="message-history" id="messages">
                    <div class="message-item info">Socket Sender Pro'ya Hoşgeldiniz</div>
                </div>

                <div class="message-input-area">
                    <div class="input-group">
                        <textarea id="message" rows="3" placeholder="Mesajınızı buraya yazın... (Shift+Enter ile alt satır, Enter ile gönder)"></textarea>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="helper-text">Çoklu mesaj için her satıra ayrı mesaj yazın.</span>
                        <div>
                            <button class="secondary" onclick="clearMessages()">Temizle</button>
                            <button onclick="sendMessage()">Gönder 🚀</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 2: Proxy -->
            <div id="tab-proxy" class="tab-content">
                <div class="page-content">
                    <div class="card">
                        <h2 style="margin-bottom: 20px;">Proxy Yapılandırması</h2>
                        <div class="input-group">
                            <label>Proxy URL</label>
                            <input type="text" id="proxyURL" placeholder="http://127.0.0.1:8888 (HTTP) veya socks5://...">
                            <p class="helper-text">Trafik izleme veya tünelleme için proxy sunucusu tanımlayın.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="setProxy()">Ayarları Kaydet</button>
                            <button class="danger" onclick="removeProxy()">Proxy'yi Devre Dışı Bırak</button>
                        </div>
                        <div id="proxyCurrentStatus" style="margin-top: 20px; padding: 15px; background: var(--bg-dark); border-radius: 8px;">
                            Mevcut Durum: <strong>Devre Dışı</strong>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 3: Headers -->
            <div id="tab-headers" class="tab-content">
                <div class="page-content">
                    <div class="card" style="margin-bottom: 30px;">
                        <h2 style="margin-bottom: 20px;">Hızlı Ekle</h2>
                        <div class="input-group">
                            <label>Raw Headers</label>
                            <textarea id="rawHeaders" rows="5" placeholder="Authorization: Bearer token...&#10;Origin: https://example.com"></textarea>
                            <p class="helper-text">Header'ları "Key: Value" formatında alt alta yapıştırın.</p>
                        </div>
                        <button onclick="parseAndAddHeaders()">Toplu Ekle</button>
                    </div>

                    <div class="card">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                            <h2>Aktif Header'lar</h2>
                            <button class="secondary" onclick="clearAllHeaders()" style="font-size: 0.8rem; padding: 8px 16px;">Tümünü Temizle</button>
                        </div>
                        
                        <div class="input-group" style="display: flex; gap: 10px;">
                            <input type="text" id="headerKey" placeholder="Key (örn. Cookie)">
                            <input type="text" id="headerValue" placeholder="Value">
                            <button onclick="addHeader()" style="white-space: nowrap;">Ekle +</button>
                        </div>

                        <div class="header-list" id="headersList">
                            <!-- Headers will be injected here -->
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        // --- UI Logic ---
        function switchTab(tabId) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

            // Show selected tab
            document.getElementById(tabId).classList.add('active');
            
            // Update Nav
            const navIndex = ['tab-messages', 'tab-proxy', 'tab-headers'].indexOf(tabId);
            document.querySelectorAll('.nav-item')[navIndex].classList.add('active');

            // Update Title
            const titles = ['Mesajlaşma', 'Proxy Ayarları', 'Header Yönetimi'];
            document.getElementById('pageTitle').innerText = titles[navIndex];
        }

        // --- WebSocket Logic ---
        let ws = null;
        let lastSentMessage = null;

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';
            
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                addLog('Sistem: Web arayüzü bağlandı', 'info');
                ws.send(JSON.stringify({ action: 'getStatus' }));
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleMessage(data);
            };

            ws.onclose = () => {
                updateConnectionStatus({ connected: false });
                setTimeout(connectWebSocket, 2000);
            };
        }

        function handleMessage(data) {
            if (data.status) {
                updateConnectionStatus(data.status);
            }

            switch (data.type) {
                case 'received':
                    addLog(data.data, 'received');
                    break;
                case 'sent':
                    if (data.data !== lastSentMessage) {
                        addLog(data.data, 'sent');
                    }
                    lastSentMessage = null;
                    break;
                case 'error':
                    addLog(data.error || data.message, 'error');
                    break;
                case 'info':
                case 'connected':
                case 'disconnected':
                case 'success':
                    addLog(data.message, 'info');
                    break;
            }
        }

        // --- Socket Actions ---
        function connect() {
            const address = document.getElementById('address').value;
            if (!address) return alert('Adres giriniz');
            ws.send(JSON.stringify({ action: 'connect', address: address }));
        }

        function disconnect() {
            ws.send(JSON.stringify({ action: 'disconnect' }));
        }

        async function sendMessage() {
            const input = document.getElementById('message');
            const text = input.value.trim();
            if (!text) return;

            const lines = text.split('\n').filter(l => l.trim().length > 0);

            if (lines.length === 1) {
                lastSentMessage = lines[0];
                ws.send(JSON.stringify({ action: 'send', data: lines[0] }));
                addLog(lines[0], 'sent');
            } else {
                for (let line of lines) {
                    lastSentMessage = line;
                    ws.send(JSON.stringify({ action: 'send', data: line }));
                    addLog(line, 'sent');
                    await new Promise(r => setTimeout(r, 50));
                }
            }
            input.value = '';
        }

        function setProxy() {
            const url = document.getElementById('proxyURL').value.trim();
            ws.send(JSON.stringify({ action: 'setProxy', proxyURL: url }));
        }

        function removeProxy() {
            ws.send(JSON.stringify({ action: 'setProxy', proxyURL: '' }));
            document.getElementById('proxyURL').value = '';
        }

        // --- Headers ---
        function addHeader() {
            const key = document.getElementById('headerKey').value;
            const value = document.getElementById('headerValue').value;
            if (key && value) {
                ws.send(JSON.stringify({ action: 'setHeader', key: key, value: value }));
                document.getElementById('headerKey').value = '';
                document.getElementById('headerValue').value = '';
            }
        }

        function parseAndAddHeaders() {
            const raw = document.getElementById('rawHeaders').value;
            const lines = raw.split('\n');
            let count = 0;
            lines.forEach(line => {
                const parts = line.split(':');
                if (parts.length >= 2) {
                    const key = parts[0].trim();
                    const val = parts.slice(1).join(':').trim();
                    if (key && val) {
                        ws.send(JSON.stringify({ action: 'setHeader', key: key, value: val }));
                        count++;
                    }
                }
            });
            if(count > 0) {
                document.getElementById('rawHeaders').value = '';
                // Toast notification here conceptually
            }
        }

        function clearAllHeaders() {
            if(confirm('Tüm headerları silmek istediğine emin misin?')) {
                ws.send(JSON.stringify({ action: 'clearHeaders' }));
            }
        }

        function removeHeader(key) {
            ws.send(JSON.stringify({ action: 'removeHeader', key: key }));
        }

        // --- Helpers ---
        function addLog(msg, type) {
            const container = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = 'message-item ' + type;
            
            const meta = document.createElement('span');
            meta.className = 'message-meta';
            const now = new Date();
            meta.innerText = type.toUpperCase() + ' • ' + now.toLocaleTimeString();

            div.appendChild(meta);
            div.appendChild(document.createTextNode(msg));
            
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        function clearMessages() {
            document.getElementById('messages').innerHTML = '';
        }

        function updateConnectionStatus(status) {
            const dot = document.getElementById('statusDot');
            const text = document.getElementById('statusText');
            const addr = document.getElementById('statusAddress');
            const btnConnect = document.getElementById('btnConnect');
            const btnDisconnect = document.getElementById('btnDisconnect');

            if (status.connected) {
                dot.className = 'status-dot connected';
                text.innerText = 'BAĞLI';
                addr.innerText = status.address || 'Bilinmiyor';
                btnConnect.style.display = 'none';
                btnDisconnect.style.display = 'inline-flex';
            } else {
                dot.className = 'status-dot disconnected';
                text.innerText = 'BAĞLI DEĞİL';
                addr.innerText = '-';
                btnConnect.style.display = 'inline-flex';
                btnDisconnect.style.display = 'none';
            }

            // Proxy UI
            const proxyBadge = document.getElementById('proxyBadge');
            const proxyStatusBox = document.getElementById('proxyCurrentStatus');
            if (status.proxy && status.proxy !== "") {
                proxyBadge.classList.add('active');
                proxyStatusBox.innerHTML = 'Mevcut Durum: <strong style="color:var(--success)">' + status.proxy + '</strong>';
                document.getElementById('proxyURL').value = status.proxy;
            } else {
                proxyBadge.classList.remove('active');
                proxyStatusBox.innerHTML = 'Mevcut Durum: <strong>Devre Dışı</strong>';
            }

            // Headers UI
            const list = document.getElementById('headersList');
            list.innerHTML = '';
            if (status.headers) {
                Object.entries(status.headers).forEach(([k, v]) => {
                    const row = document.createElement('div');
                    row.className = 'header-row';
                    row.innerHTML = 
                        '<div>' +
                            '<div class="header-key">' + k + '</div>' +
                            '<div class="header-val">' + v + '</div>' +
                        '</div>' +
                        '<button class="danger" style="padding: 6px 12px; font-size: 0.75rem;" onclick="removeHeader(\'' + k + '\')">Sil</button>';
                    list.appendChild(row);
                });
            }
        }

        // --- Init ---
        // Enter to send
        document.getElementById('message').addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
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
	fmt.Println("                        - HTTP için: proxy http://localhost:8888")
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
