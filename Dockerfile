FROM python:3.12-slim

# Только stdlib: зависимостей нет. ca-certificates нужны для RDAP (HTTPS) — в образе уже есть.
WORKDIR /app
COPY app.py checker.py ./
COPY data/ ./data/
COPY static/ ./static/

RUN useradd --system --no-create-home --uid 10001 checker
USER checker

ENV HOST=0.0.0.0 \
    PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

CMD ["python3", "app.py"]
