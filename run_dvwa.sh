#!/usr/bin/env bash
set -e

echo "[START] DVWA dev environment 시작 🚀 "

# 1️⃣ Docker 설치 확인
if ! command -v docker >/dev/null 2>&1; then
    echo "[WARN]: Docker를 설치해야합니다."
    # Linux 예시 (Ubuntu)
    if [ "$(uname)" = "Linux" ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker $USER
        echo "Docker installed. Please log out/in for permissions."
        exit 0
    fi
    # macOS / Windows 안내
    echo "Please install Docker Desktop: https://docs.docker.com/get-docker/"
    exit 1
fi

# 2️⃣ Docker Compose 설치 확인
if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
    echo "[WARN]: Docker Compose를 설치해야합니다. 설치를 실행-"
    if [ "$(uname)" = "Linux" ]; then
        sudo curl -L "https://github.com/docker/compose/releases/download/v2.22.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        echo "[SUCCESS]: Docker Compose installed."
    else
        echo "[ERROR]: Docker Compose를 설치해주세요: https://docs.docker.com/compose/install/"
        exit 1
    fi
fi

# 3️⃣ DVWA Docker Compose 실행
bash infra/dev/run_dev_dvwa.sh