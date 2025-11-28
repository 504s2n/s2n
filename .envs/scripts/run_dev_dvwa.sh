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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DVWA_DIR="$SCRIPT_DIR/../dev"

cd "$DVWA_DIR" || exit 1

# .env.dev 로드
ENV_FILE=".env.dev"
if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
fi

echo "[INFO]: 📦 Docker Compose 서비스 시작 중..."
echo "       환경변수 파일: $ENV_FILE"
echo ""

# .env.dev 파일의 환경변수를 주입하여 docker compose up -d 실행
cd ../dev || exit 1
docker compose --env-file .env.dev up -d

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS]: ✅ DVWA 컨테이너들이 성공적으로 시작되었습니다."
    echo "        접속: http://localhost:${HOST_PORT}"
    echo "        중지: bash /.envs/scripts/stop_dev_dvwa.sh"
else
    echo ""
    echo "[FAIL]: ❌ Docker Compose 실행 중 오류가 발생했습니다."
    exit 1
fi
