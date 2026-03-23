# S3M NAC Policy Engine

Bu proje, kurum içi ağ erişim güvenliğini sağlamak amacıyla geliştirilmiş dinamik bir Network Access Control (NAC) politika motorudur. Sistem, FreeRADIUS üzerinden gelen ağ isteklerini asenkron bir Python (FastAPI) arka plan servisi ile işler.

## Gereksinimler
* Docker
* Docker Compose
* Git

## Kurulum ve Çalıştırma

**1. Çevresel Değişkenleri Ayarlayın:**
Örnek yapılandırma dosyasını kopyalayarak kendi `.env` dosyanızı oluşturun:
`cp .env.example .env`

**2. Sistemi Ayağa Kaldırın:**
Tüm mikroservisleri arka planda başlatın:
`docker compose up -d --build`

## Test Talimatları
Sistem ayağa kalktıktan sonra doğrulama testi yapabilirsiniz:
`docker exec -it nac_freeradius radtest admin_user supersecretpassword localhost 1812 testing123`
*Beklenen Sonuç: Access-Accept ve VLAN atama bilgisi.*
