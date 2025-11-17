# 스크립트가 있는 디렉토리로 이동
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

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
docker compose --env-file .env.dev up -d

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS]: ✅ DVWA 컨테이너들이 성공적으로 시작되었습니다."
    echo "        접속: http://localhost:${HOST_PORT}"
    echo "        중지: bash infra/dev/stop_dev_dvwa.sh"
else
    echo ""
    echo "[FAIL]: ❌ Docker Compose 실행 중 오류가 발생했습니다."
    exit 1
fi
