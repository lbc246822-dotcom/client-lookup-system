FROM python:3.12-slim
WORKDIR /app
COPY server.py index.html ./
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    HOST=0.0.0.0 \
    CHANNEL_DB=/data/channel.sqlite3
EXPOSE 8080
CMD ["python", "server.py"]
