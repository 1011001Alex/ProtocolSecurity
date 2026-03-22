# Protocol Security - Quick Start Scripts
# Created by Theodor Munch
# Copyright (c) 2026 Theodor Munch. All rights reserved.

# Quick Deploy (Development)
docker-compose up -d

# View Status
docker-compose ps

# View Logs
docker-compose logs -f protocol-security

# Health Check
curl http://localhost:3000/health

# Stop
docker-compose down

# Rebuild
docker-compose up -d --build

# Production Deploy
docker-compose --profile monitoring up -d

# Kubernetes Deploy
kubectl apply -f k8s/

# Run Tests
npm test

# Build
npm run build

# Security Audit
npm audit

# Docker Build
docker build -t protocol-security:latest .

# Docker Run
docker run -d --name protocol-security -p 3000:3000 --env-file .env protocol-security:latest
