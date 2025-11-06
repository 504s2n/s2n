# 추후 /core 패키지 구성 완료 이후 로컬 개발 환경과 통합용 이미지 빌드

FROM python:3.11-slim

# # 시스템 패키지 설치
# RUN apt-get update && apt-get install -y \
#     apache2 \
#     mysql-server \
#     nodejs \
#     npm \
#     curl \
#     git \
#     && rm -rf /var/lib/apt/lists/*

# # 최신 pnpm 설치
# RUN npm install -g pnpm@9

# # uv 설치
# RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# WORKDIR /workspace

# # Python 의존성 설치
# COPY ../../pyproject.toml ./pyproject.toml
# RUN uv sync

# # Node 의존성 설치
# COPY ../../pnpm-workspace.yaml ./pnpm-workspace.yaml
# COPY ../../cli/package.json ./cli/package.json
# COPY ../../aws/package.json ./aws/package.json
# RUN pnpm install --recursive

# CMD ["bash", "-c", "service mysql start && service apache2 start && tail -f /dev/null"]