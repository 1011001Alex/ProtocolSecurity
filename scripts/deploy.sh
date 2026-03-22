#!/bin/bash

# =============================================================================
# Quick Deploy Script for Protocol Security
# =============================================================================
# Usage: ./scripts/deploy.sh [environment]
# Environments: development, staging, production
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-development}
PROJECT_NAME="protocol-security"

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

# =============================================================================
# Pre-deployment Checks
# =============================================================================

pre_deployment_checks() {
    log_info "Running pre-deployment checks..."
    
    # Check required commands
    check_command node
    check_command npm
    check_command docker
    check_command docker-compose
    
    # Check Node.js version
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        log_error "Node.js version must be 18 or higher"
        exit 1
    fi
    
    # Check if .env file exists
    if [ ! -f ".env" ]; then
        log_warning ".env file not found. Copying from .env.example..."
        cp .env.example .env
        log_warning "Please update .env file with your configuration"
        exit 1
    fi
    
    log_success "Pre-deployment checks passed"
}

# =============================================================================
# Build Application
# =============================================================================

build_application() {
    log_info "Building application..."
    
    # Install dependencies
    npm ci
    
    # Run linter
    npm run lint
    
    # Run tests
    npm test -- --coverage
    
    # Build TypeScript
    npm run build
    
    log_success "Application built successfully"
}

# =============================================================================
# Deploy to Docker
# =============================================================================

deploy_docker() {
    log_info "Deploying to Docker..."
    
    # Build Docker image
    docker build -t ${PROJECT_NAME}:latest .
    
    # Stop existing container
    docker stop ${PROJECT_NAME} 2>/dev/null || true
    docker rm ${PROJECT_NAME} 2>/dev/null || true
    
    # Run new container
    docker run -d \
        --name ${PROJECT_NAME} \
        -p 3000:3000 \
        --env-file .env \
        --restart unless-stopped \
        ${PROJECT_NAME}:latest
    
    log_success "Deployed to Docker successfully"
}

# =============================================================================
# Deploy to Docker Compose
# =============================================================================

deploy_compose() {
    log_info "Deploying with Docker Compose..."
    
    # Stop existing services
    docker-compose down
    
    # Build and start services
    docker-compose up -d --build
    
    log_success "Deployed with Docker Compose successfully"
}

# =============================================================================
# Health Checks
# =============================================================================

health_check() {
    log_info "Running health checks..."
    
    # Wait for application to start
    sleep 10
    
    # Check if container is running
    if docker ps | grep -q ${PROJECT_NAME}; then
        log_success "Container is running"
    else
        log_error "Container is not running"
        exit 1
    fi
    
    # Check health endpoint
    HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
    
    if [ "$HEALTH_RESPONSE" -eq 200 ]; then
        log_success "Health check passed (HTTP $HEALTH_RESPONSE)"
    else
        log_error "Health check failed (HTTP $HEALTH_RESPONSE)"
        exit 1
    fi
    
    log_success "All health checks passed"
}

# =============================================================================
# View Logs
# =============================================================================

view_logs() {
    log_info "Viewing application logs..."
    docker logs -f ${PROJECT_NAME}
}

# =============================================================================
# Main Deployment Flow
# =============================================================================

main() {
    echo "============================================="
    echo "  Protocol Security Deployment Script"
    echo "  Environment: $ENVIRONMENT"
    echo "============================================="
    echo ""
    
    case $ENVIRONMENT in
        development)
            pre_deployment_checks
            build_application
            deploy_docker
            health_check
            ;;
        staging|production)
            log_warning "For $ENVIRONMENT deployment, use CI/CD pipeline"
            log_info "GitHub Actions will handle deployment to $ENVIRONMENT"
            exit 0
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            echo "Usage: $0 [development|staging|production]"
            exit 1
            ;;
    esac
    
    echo ""
    echo "============================================="
    log_success "Deployment completed successfully!"
    echo "============================================="
    echo ""
    echo "Application URL: http://localhost:3000"
    echo "Health check: http://localhost:3000/health"
    echo ""
    echo "To view logs: docker logs -f ${PROJECT_NAME}"
    echo "To stop: docker stop ${PROJECT_NAME}"
    echo ""
}

# Run main function
main "$@"
