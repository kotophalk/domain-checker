#!/bin/bash
# Обновление боевой копии до состояния origin/main.
#
# Запускается двумя способами:
#   - из GitHub Actions по SSH (в authorized_keys прописан как forced command,
#     поэтому ключ деплоя не может выполнить ничего другого);
#   - руками: /opt/domain-checker/deploy/update.sh
set -euo pipefail

# Один деплой на сервере за раз. Три инструмента (slovostat, domain-checker,
# domenomer) живут на одной машине и делят Docker; параллельные `docker build`
# и `docker image prune` гоняются (16.08.2026: два деплоя из трёх упали с
# «a prune operation is already running» / containerd race). Лок общий для всех
# трёх update.sh; ждём очередь до 10 минут, а не падаем.
LOCK=/tmp/lulu-deploy.lock
exec 9>"$LOCK"
if ! flock -w 600 9; then
	echo "не дождался очереди деплоя (${LOCK}) за 10 минут" >&2
	exit 1
fi

cd /opt/domain-checker

PORT="$(sed -n 's/^DOMAIN_CHECKER_PORT=//p' .env 2>/dev/null | head -1)"
PORT="${PORT:-8002}"

echo "=== git ==="
git fetch --prune origin
# ff-only: если на сервере оказались локальные правки, деплой упадёт заметно,
# а не затрёт их молча.
git pull --ff-only

echo "=== сборка и запуск ==="
docker compose up -d --build
docker image prune -f

echo "=== состояние ==="
docker compose ps

echo "=== проверка здоровья ==="
for _ in $(seq 20); do
	if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/healthz" > /dev/null; then
		echo "сервис отвечает"
		exit 0
	fi
	sleep 1
done

echo "сервис не поднялся: /healthz молчит 20 секунд" >&2
docker compose logs --tail 50
exit 1
