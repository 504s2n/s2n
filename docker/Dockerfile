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

# 빌드 결과 복사 및 설치
COPY --from=builder /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && \
    rm -rf /dist /root/.cache/pip

# s2n 패키지가 wheel에 포함되어 있으므로 소스 복사 불필요
# 진입점: CLI 도구이므로 컨테이너를 계속 실행하려면 tail 사용
# 실제 사용 시에는 docker run 명령에서 s2n 명령을 직접 지정
CMD ["tail", "-f", "/dev/null"]