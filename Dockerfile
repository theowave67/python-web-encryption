# Dockerfile
# ========= 多阶段构建：安装依赖 =========
FROM python:3.12-slim AS builder
WORKDIR /app

# 【国内高速 apt 源】阿里云，超快！
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# 【pip 清华源】永久生效 + 超时加大
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    PIP_NO_CACHE_DIR=1

# 复制 requirements 先缓存层
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# ========= 最终运行镜像 =========
FROM python:3.12-slim
WORKDIR /app

# 【运行时也换 apt 国内源 + 安装 curl/ca-certificates】
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# pip 国内源（运行时可能需要 pip install 额外包）
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    PIP_NO_CACHE_DIR=1

# 复制 Python 依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 复制应用文件
COPY app.py .
COPY requirements.txt .
COPY zeabur-data/ zeabur-data/

EXPOSE 8000

# 健康检查（带启动宽限期）
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD python -c "import requests; exit(0 if requests.get('http://localhost:8000').status_code == 200 else 1)" || exit 1


CMD ["python", "app.py", "--encrypted", "zeabur-data/silasvivid-outlook.data.enc", "--run-http"]
