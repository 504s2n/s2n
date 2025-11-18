# For Dev branch merge - Docker image build and push to GHCR

FROM python:3.11-slim AS builder
WORKDIR /src

# 최소한의 빌드 툴 설치 (필요시 조정)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 메타데이터 먼저 복사해서 캐시 활용
COPY pyproject.toml setup.cfg* /src/

# 전체 소스 복사
COPY . /src

# 빌드 툴 설치 및 wheel 생성
RUN python -m pip install --upgrade pip build setuptools wheel && \
    python -m build --wheel --outdir /dist

# --------------------------
# runtime image
# --------------------------
FROM python:3.11-slim
WORKDIR /app

# (선택) 런타임 의존성 설치를 위해 requirements.txt가 필요하면 복사/설치
# COPY requirements-dev.txt /app/
# RUN pip install --no-cache-dir -r /app/requirements.txt

# 빌드 결과 복사 및 설치
COPY --from=builder /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /root/.cache/pip

# 애플리케이션 소스(필요시 최소 범위만 복사)
COPY . .

# 기존과 동일한 진입점 유지 (필요시 변경)
CMD ["python", "main.py"]