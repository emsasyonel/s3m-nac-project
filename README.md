# S3M NAC Policy Engine

Bu proje, kurum içi ağ erişim güvenliğini sağlamak amacıyla geliştirilmiş dinamik bir Network Access Control (NAC) politika motorudur. Sistem, FreeRADIUS üzerinden gelen ağ isteklerini asenkron bir Python (FastAPI) arka plan servisi ile işler.

## 🚀 Özellikler
* **Kimlik Doğrulama (Authentication):** PAP (Bcrypt şifreleme) ve MAB (MAC tabanlı) doğrulama.
* **Yetkilendirme (Authorization):** Kullanıcı gruplarına (admin, employee, guest) göre dinamik VLAN (Tunnel-Private-Group-Id) ataması.
* **Hesap Yönetimi (Accounting):** Oturum başlangıç/bitiş verilerinin PostgreSQL'e kaydedilmesi ve aktif oturumların Redis üzerinden anlık izlenmesi.
* **Güvenlik (Rate Limiting):** Ardışık 3 hatalı girişte kullanıcının Redis üzerinden 5 dakika süreyle engellenmesi.

## 🛠️ Gereksinimler
* Docker ve Docker Compose
* Git

## ⚙️ Kurulum ve Çalıştırma

**1. Projeyi Klonlayın:**
`git clone <sizin-github-repo-linkiniz>`
`cd s3m-nac-project`

**2. Çevresel Değişkenleri Ayarlayın:**
Projeyi çalıştırmadan önce örnek `.env.example` dosyasını kopyalayarak kendi `.env` dosyanızı oluşturun:
`cp .env.example .env`

**3. Sistemi Ayağa Kaldırın:**
Tüm mikroservisleri (PostgreSQL, Redis, FreeRADIUS, FastAPI) arka planda başlatmak ve imajları derlemek için aşağıdaki komutu çalıştırın:
`docker compose up -d --build`

**4. Servis Durumlarını Kontrol Edin:**
Sistemin sağlıklı çalıştığından emin olmak için çalışan container'ları listeleyin:
`docker ps`
*(Ekranda nac_freeradius, nac_fastapi, nac_postgres ve nac_redis container'larının Up durumunda olduğunu görmelisiniz).*

## 🧪 Test Adımları

Sistem ayağa kalktıktan sonra aşağıdaki adımlarla projeyi test edebilirsiniz:

**1. Yeni Bir Kullanıcı Oluşturma (API üzerinden):**
`curl -X POST http://localhost:8000/users -H "Content-Type: application/json" -d '{"username": "admin_user", "password": "supersecretpassword", "groupname": "admin"}'`

**2. RADIUS Kimlik Doğrulama ve VLAN Testi:**
`docker exec -it nac_freeradius radtest admin_user supersecretpassword localhost 1812 testing123`
*(Başarılı giriş durumunda Access-Accept ve Tunnel-Private-Group-Id:0 = "10" dönmelidir).*

**3. Hız Sınırı (Rate Limit) Testi:**
Yukarıdaki radtest komutunu bilerek 3 kere yanlış şifreyle denediğinizde, sistemin sizi 5 dakikalığına banladığını görebilirsiniz.

**4. Aktif Oturumları Görüntüleme:**
`curl http://localhost:8000/sessions/active`

## 📝 Logları İnceleme
Policy Engine (FastAPI) tarafında arka planda dönen işlemleri ve veritabanı sorgularını canlı izlemek için:
`docker logs -f nac_fastapi`
