echo "[STOP] Local Dev DVWA environment 중지 🛑 "
# 스크립트가 있는 디렉토리로 이동
pwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DVWA_DIR="$SCRIPT_DIR/../dev"

cd "$DVWA_DIR" || exit 1

docker compose --env-file .env.dev down -v
