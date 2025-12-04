# Socket Sender

Modern ve kullanıcı dostu bir socket client uygulaması. TCP, WebSocket (WS) ve WebSocket Secure (WSS) bağlantıları kurarak veri gönderebilir ve alabilirsiniz. Hem CLI hem de web arayüzü desteği ile gelir.

## 🚀 Özellikler

- **Çoklu Protokol Desteği**: TCP, WebSocket (WS) ve WebSocket Secure (WSS)
- **CLI Desteği**: Terminal üzerinden tam kontrol
- **Proxy Desteği**: HTTP ve SOCKS5 proxy desteği (Charles Proxy uyumlu)
- **Çoklu Mesaj Gönderme**: Birden fazla mesajı tek seferde gönderme
- **Header Yönetimi**: WebSocket bağlantıları için özel header'lar ekleme
- **Gerçek Zamanlı Mesajlaşma**: Gelen ve giden mesajları gerçek zamanlı görüntüleme
- **Bağlantı Yönetimi**: Otomatik ping-pong mekanizması ile bağlantıyı canlı tutma
- **Mesaj Geçmişi**: Tüm mesajları görüntüleme ve temizleme

## 📋 Gereksinimler

- Go 1.21 veya üzeri
- Modern bir web tarayıcısı (web arayüzü için)

## 🔧 Kurulum

### Kaynak Koddan Derleme

```bash
# Repository'yi klonlayın
git clone https://github.com/02gur/socketSender.git
cd socketSender

# Bağımlılıkları yükleyin
go mod download

# Programı derleyin
go build -o socketSender

# Veya doğrudan çalıştırın
go run main.go
```

### Cross-Platform Build

Projeyi Windows, Linux ve macOS için derlemek için build scriptlerini kullanabilirsiniz:

**Linux/macOS:**
```bash
chmod +x build.sh
./build.sh
```

**Windows:**
```cmd
build.bat
```

Build scriptleri tüm platformlar için binary'leri `build/` dizininde oluşturur:
- Linux (amd64, 386, arm64, arm)
- Windows (amd64, 386, arm64)
- macOS (amd64, arm64)

Her binary için SHA256 checksum dosyaları da otomatik oluşturulur.

Program başladığında:
- CLI arayüzü terminalde açılır
- Web arayüzü `http://localhost:8080` adresinde çalışır


#### Bağlantı Kurma

```bash
# TCP bağlantısı
socket> connect localhost:8080

# WebSocket bağlantısı
socket> connect ws://localhost:8080/ws

# WebSocket Secure bağlantısı
socket> connect wss://api.example.com/v2
```

#### Mesaj Gönderme

```bash
# Tek mesaj
socket> send [1,"test"]

# Çoklu mesaj (|| ile ayrılmış)
socket> send [1,"test"] || [2,"test2"] || [3,"test3"]
```

#### Header Yönetimi

```bash
# Header ekle
socket> header Origin https://example.com
socket> header Authorization Bearer token123

# Header listele
socket> list-headers

# Header kaldır
socket> remove-header Origin

# Tüm header'ları temizle
socket> clear-headers
```

#### Proxy Ayarlama

```bash
# HTTP proxy (Tested Charles Proxy)
socket> proxy http://localhost:8888

# SOCKS5 proxy
socket> proxy socks5://127.0.0.1:1080

# Proxy'yi kapat
socket> proxy-off
```

#### Diğer Komutlar

```bash
# Bağlantı durumunu kontrol et
socket> status

# Bağlantıyı kapat
socket> disconnect

# Yardım
socket> help

# Çıkış
socket> exit
```

### Web Arayüzü

1. Tarayıcınızda `http://localhost:8080` adresine gidin
2. **Bağlantı** bölümünden:
   - Proxy ayarlarını yapın (opsiyonel)
   - Socket adresini girin
   - "Bağlan" butonuna tıklayın
3. **Mesaj Gönder** bölümünden:
   - Tek mesaj için: Mesajı yazın ve "Gönder" butonuna tıklayın
   - Çoklu mesaj için: Her satıra bir mesaj yazın ve "Gönder" butonuna tıklayın
4. **Header Yönetimi** bölümünden:
   - Raw header'ları yapıştırın veya tek tek ekleyin
5. **Mesaj Geçmişi** bölümünden:
   - Tüm gelen ve giden mesajları görüntüleyin
   - Mesaj geçmişini temizleyin

### Web Arayüzü Özellikleri

- **Otomatik Scroll**: Yeni mesajlar geldiğinde otomatik olarak en alta kaydırır
- **Enter ile Gönderme**: Enter tuşuna basarak mesaj gönderebilirsiniz (Shift+Enter ile yeni satır)
- **Gerçek Zamanlı Güncellemeler**: Bağlantı durumu ve mesajlar gerçek zamanlı güncellenir
- **Mesaj Formatı**: 
  - `sender:` ile başlayan mesajlar gönderilen mesajlardır
  - `receiver:` ile başlayan mesajlar alınan mesajlardır

## 🔐 Proxy Kullanımı (Charles Proxy)

Proxy ile trafiği izlemek için:

1. Proxy'yi başlatın
2. Programda proxy'yi ayarlayın:
   ```bash
   socket> proxy http://localhost:8888
   ```
   veya web arayüzünden "Proxy" alanına `http://localhost:8888` yazın
3. Socket bağlantısı yapın
4. Tüm trafik Proxy'de görünecektir


## 📦 Bağımlılıklar

- `github.com/gorilla/websocket` - WebSocket desteği
- `github.com/chzyer/readline` - CLI ok tuşları ve geçmiş desteği
- `golang.org/x/net/proxy` - Proxy desteği


## 👤 Yazar

**02gur**

## 🙏 Teşekkürler

- [Gorilla WebSocket](https://github.com/gorilla/websocket) - WebSocket kütüphanesi
- [Readline](https://github.com/chzyer/readline) - CLI geliştirme kütüphanesi

## 📞 İletişim

Sorularınız veya önerileriniz için issue açabilirsiniz.

---

⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!

