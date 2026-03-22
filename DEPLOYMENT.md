# DEPLOYMENT GUIDE

> **Полное руководство по развёртыванию Protocol Security**  
> **Created by Theodor Munch**

[![Deployment: Docker](https://img.shields.io/badge/deployment-docker-blue)](https://www.docker.com/)
[![Deployment: Kubernetes](https://img.shields.io/badge/deployment-kubernetes-blue)](https://kubernetes.io/)
[![CI/CD: GitHub Actions](https://img.shields.io/badge/cicd-github%20actions-blue)](https://github.com/features/actions)

---

## 📋 Содержание

- [🚀 Быстрый старт](#-быстрый-старт)
- [📦 Docker Deployment](#-docker-deployment)
- [☸️ Kubernetes Deployment](#️-kubernetes-deployment)
- [🔄 CI/CD Pipeline](#-cicd-pipeline)
- [🔧 Конфигурация](#-конфигурация)
- [📊 Monitoring](#-monitoring)
- [🔐 Security](#-security)
- [🐛 Troubleshooting](#-troubleshooting)

---

## 🚀 Быстрый старт

### 1. Клонирование

```bash
git clone https://github.com/protocol/security.git
cd security
```

### 2. Настройка окружения

```bash
# Копирование примера
cp .env.example .env

# Редактирование .env
nano .env  # или ваш любимый редактор
```

### 3. Запуск (Docker)

```bash
# Быстрый запуск
docker-compose up -d

# Проверка статуса
docker-compose ps

# Просмотр логов
docker-compose logs -f protocol-security
```

### 4. Проверка

```bash
# Health check
curl http://localhost:3000/health

# Должно вернуть:
# {"status":"healthy","timestamp":"2026-03-22T..."}
```

---

## 📦 Docker Deployment

### Файлы

- `Dockerfile` - Multi-stage build
- `docker-compose.yml` - Full stack
- `.dockerignore` - Исключения

### Команды

```bash
# Build образа
docker build -t protocol-security:latest .

# Запуск контейнера
docker run -d \
  --name protocol-security \
  -p 3000:3000 \
  --env-file .env \
  protocol-security:latest

# Docker Compose (все сервисы)
docker-compose up -d

# Остановка
docker-compose down

# Пересборка
docker-compose up -d --build
```

### Сервисы в docker-compose

| Сервис | Порт | Описание |
|--------|------|----------|
| protocol-security | 3000 | Основное приложение |
| redis | 6379 | Сессии, rate limiting |
| elasticsearch | 9200 | Log storage |
| vault | 8200 | Secrets management |
| kibana | 5601 | Visualization (siem) |
| grafana | 3001 | Monitoring (monitoring) |
| prometheus | 9090 | Metrics (monitoring) |

---

## ☸️ Kubernetes Deployment

### Файлы

- `k8s/deployment.yaml` - Deployment, Service, Ingress, HPA
- `k8s/configmap.yaml` - Конфигурация
- `k8s/secrets.yaml` - Секреты
- `k8s/namespace.yaml` - Namespace

### Развёртывание

```bash
# Создание namespace
kubectl create namespace protocol-security

# Применение манифестов
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/deployment.yaml

# Проверка статуса
kubectl get pods -n protocol-security
kubectl get svc -n protocol-security

# Масштабирование
kubectl scale deployment protocol-security --replicas=5 -n protocol-security

# Обновление
kubectl rollout restart deployment/protocol-security -n protocol-security

# Откат
kubectl rollout undo deployment/protocol-security -n protocol-security
```

### Характеристики

- **Replicas:** 3 (min) - 10 (max)
- **Auto-scaling:** CPU > 70%, Memory > 80%
- **Health checks:** Liveness & Readiness probes
- **Network policies:** Restricted ingress/egress
- **Security context:** Non-root user

---

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

**Файл:** `.github/workflows/ci-cd.yml`

### Этапы

```
┌─────────────┐
│    Lint     │ Security & Code Quality
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Test     │ Unit & Integration Tests
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Build    │ TypeScript & Docker
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Staging   │ Deploy to Staging
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Production  │ Deploy to Production (on release)
└─────────────┘
```

### Триггеры

- **Push to develop:** Deploy to staging
- **Release published:** Deploy to production
- **Pull request:** Run tests only

### Команды

```bash
# Локальный запуск тестов
npm test

# Запуск security audit
npm audit

# Build
npm run build

# Docker build
docker build -t protocol-security:latest .
```

---

## 🔧 Конфигурация

### Переменные окружения

#### Основные

```bash
# Environment
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Crypto
CRYPTO_PROVIDER=aws-kms
CRYPTO_KEY_ID=arn:aws:kms:...

# Auth
JWT_ISSUER=https://auth.protocol.local
MFA_REQUIRED=true

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=secret

# Vault
VAULT_URL=https://vault.local:8200
VAULT_TOKEN=hvs.xxxxx

# Elasticsearch
ELASTICSEARCH_HOST=https://es.local:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=secret

# Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_ROUTING_KEY=xxxxx
```

### ConfigMap (Kubernetes)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: protocol-config
data:
  redis-host: "redis.protocol-security.svc"
  elasticsearch-host: "elasticsearch.protocol-security.svc"
  log-level: "info"
```

### Secrets (Kubernetes)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: protocol-secrets
type: Opaque
stringData:
  redis-password: "secret"
  vault-token: "hvs.xxxxx"
```

---

## 📊 Monitoring

### Prometheus Metrics

**Endpoint:** `/metrics`

**Метрики:**
- `http_requests_total` - Всего запросов
- `http_request_duration_seconds` - Длительность запросов
- `security_events_total` - Security события
- `auth_attempts_total` - Попытки аутентификации
- `rate_limit_hits_total` - Rate limit срабатывания

### Grafana Dashboards

**ID:** 3001

**Dashboards:**
- Security Overview
- Application Performance
- Error Rates
- Threat Detection

### Alerts

```yaml
# alerts/security-alerts.yml
groups:
  - name: security
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High error rate detected"
      
      - alert: BruteForceDetected
        expr: rate(auth_attempts_total{status="failed"}[5m]) > 10
        for: 2m
        annotations:
          summary: "Possible brute force attack"
```

---

## 🔐 Security

### Best Practices

✅ **Non-root user** - Приложение запускается от non-root  
✅ **Read-only filesystem** - Root filesystem read-only  
✅ **Security headers** - Все headers настроены  
✅ **TLS/SSL** - Шифрование трафика  
✅ **Secrets management** - Vault для секретов  
✅ **Network policies** - Ограничение трафика  
✅ **Resource limits** - CPU/Memory лимиты

### Security Scanning

```bash
# Docker image scanning
docker scan protocol-security:latest

# Snyk security scan
snyk test

# Gitleaks (secrets detection)
gitleaks detect
```

---

## 🐛 Troubleshooting

### Логи

```bash
# Docker
docker logs protocol-security

# Docker Compose
docker-compose logs -f protocol-security

# Kubernetes
kubectl logs -f deployment/protocol-security -n protocol-security
```

### Debug mode

```bash
# Включить debug логи
LOG_LEVEL=debug

# Verbose mode
DEBUG=protocol-security:*
```

### Частые проблемы

#### 1. Container не запускается

```bash
# Проверка логов
docker logs protocol-security

# Проверка портов
docker ps
netstat -tulpn | grep 3000
```

#### 2. Health check fails

```bash
# Проверка health endpoint
curl http://localhost:3000/health

# Проверка зависимостей
docker-compose ps
```

#### 3. Redis connection error

```bash
# Проверка Redis
docker-compose exec redis redis-cli ping

# Проверка пароля
docker-compose exec redis redis-cli AUTH password
```

#### 4. Vault connection error

```bash
# Проверка Vault
curl http://localhost:8200/v1/sys/health

# Проверка токена
export VAULT_TOKEN=hvs.xxxxx
vault status
```

---

## 👤 Author

**Theodor Munch**  
*Creator & Lead Developer*

**Copyright:** © 2026 Theodor Munch. All rights reserved.

---

## 📞 Support

- **Documentation:** https://docs.protocol.local
- **Issues:** https://github.com/protocol/security/issues
- **Slack:** #protocol-security

---

**Created by:** Theodor Munch  
**Дата обновления:** 22 марта 2026 г.  
**Версия:** 1.0.0  
**Copyright:** © 2026 Theodor Munch. All rights reserved.
