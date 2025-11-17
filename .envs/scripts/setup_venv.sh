#!/usr/bin/env bash
set -e  # 오류 발생 시 중단

# === 기본 경로 설정 ===
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="$ROOT_DIR/.envs/python"
VENV_DIR="$ENV_DIR/.venv"
PYTHON_VERSION_FILE="$ENV_DIR/.python-version"
PYPROJECT_FILE="$ENV_DIR/pyproject.toml"
REQUIREMENTS_FILE="$ENV_DIR/requirements.txt"

# === Python 버전 탐색 ===
echo "🔍 Detecting Python version..."

if [[ -f "$PYTHON_VERSION_FILE" ]]; then
  PY_VERSION=$(cat "$PYTHON_VERSION_FILE" | tr -d '[:space:]')
  echo "📘 Found .python-version: $PY_VERSION"
elif [[ -f "$PYPROJECT_FILE" ]]; then
  PY_VERSION=$(grep -E '^python\s*=' "$PYPROJECT_FILE" | head -n1 | sed -E 's/.*"(.*)".*/\1/')
  echo "📘 Found pyproject.toml Python version: $PY_VERSION"
else
  echo "⚠️  No .python-version or pyproject.toml found. Using system default python."
  PY_VERSION=""
fi

# === Python 실행 파일 찾기 ===
if [[ -n "$PY_VERSION" ]]; then
  if ! pyenv versions --bare | grep -Fx "$PY_VERSION" >/dev/null 2>&1; then
    echo "⬇️  Installing Python $PY_VERSION via pyenv..."
    pyenv install -s "$PY_VERSION"
  fi
  export PYENV_VERSION="$PY_VERSION"
  PY_BIN="$(pyenv which python)"
else
  # 버전 미지정 시, pyenv 우선 사용 후 시스템 파이썬으로 폴백
  PY_BIN="$(pyenv which python 2>/dev/null || command -v python3 || command -v python)"
fi

if [[ -z "$PY_BIN" ]]; then
  echo "❌ Python interpreter not found."
  exit 1
fi

echo "✅ Using Python: $PY_BIN"

# === 가상환경 생성 ===
if [[ -d "$VENV_DIR" ]]; then
  echo "♻️  Existing virtual environment found at $VENV_DIR"
else
  echo "⚙️  Creating virtual environment at $VENV_DIR ..."
  "$PY_BIN" -m venv "$VENV_DIR"
fi

# === requirements 설치 ===
if [[ -f "$REQUIREMENTS_FILE" ]]; then
  echo "📦 Installing development dependencies..."
  "$VENV_DIR/bin/pip" install --upgrade pip
  "$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE"
else
  echo "ℹ️  No requirements.txt found. Skipping."
fi

echo "✅ Virtual environment setup complete!"
echo "👉 To activate: source $VENV_DIR/bin/activate"

while true; do
  read -p "Activate s2n/.envs/python/.venv? [y/n]: " -n 1 -r yn
  echo
      case $yn in
          [Yy])
              source $VENV_DIR/bin/activate
              echo "[ACTIVATED]:✅ common .VENV activated"
              break
              ;;
          [Nn])
              echo "[N]: finishing scripts..."
              exit 1 # 스크립트를 종료합니다.
              ;;
          *)
              echo "Wrong command"
              # *은 위의 어떤 패턴과도 일치하지 않을 경우 실행됩니다.
              ;;
      esac
done  

echo "[FIN]: ✅ Dev VENV Completed"