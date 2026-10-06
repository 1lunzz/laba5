# Лабораторная работа №5 — безопасность Flask API

Автор: Болатов Нурболат, группа ИС-232/2.

## Файлы

- `app.py` — защищённый API (основное приложение).
- `vulnerable_app.py` — намеренно уязвимый учебный вариант для сравнения.
- `test_security.py` — 18 автоматизированных проверок.
- `requirements.txt` — версии зависимостей.
- `openapi.json` — описание GET, POST и DELETE для ZAP.
- `zap-rules.tsv` — правила оценки находок ZAP.
- `.github/workflows/security.yml` — GitHub Actions.
- `results/` — результаты выполненных локальных pytest и Bandit.

## Windows 11 / PowerShell

Открой терминал в распакованной папке `lab5_security`. Для воспроизведения
среды отчёта используй Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:USER_TOKEN = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
$env:ADMIN_TOKEN = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe app.py
```

Приложение: `http://127.0.0.1:5000`. Проверка готовности:
`http://127.0.0.1:5000/health`.

Проверки можно выполнить после остановки сервера (Ctrl+C) или в другом терминале:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m bandit -r app.py
# Для сравнения: ожидаются находки и ненулевой код завершения.
.\.venv\Scripts\python.exe -m bandit -r vulnerable_app.py
```

## Пример обращения к API

В отдельном PowerShell-терминале установи ADMIN_TOKEN равным значению,
использованному при запуске сервера. Новый случайный токен не подойдёт.
Для примера ниже приложение должно продолжать работать.

```powershell
$env:ADMIN_TOKEN = "ТОКЕН_ИЗ_ТЕРМИНАЛА_СЕРВЕРА"
$headers = @{ Authorization = "Bearer $env:ADMIN_TOKEN" }
$body = @{ name = "Alice"; email = "alice@example.test" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/users -Headers $headers -ContentType "application/json" -Body $body
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:5000/api/users -Headers $headers
Invoke-RestMethod -Method Delete -Uri http://127.0.0.1:5000/api/users/1 -Headers $headers
```

Обычный токен USER_TOKEN разрешает только чтение. Без токена возвращается
401; запись с токеном пользователя возвращает 403. Валидация использует
ограниченный учебный формат имени и email. Токены задаются через окружение,
должны различаться и содержать минимум 32 символа.

## Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export USER_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

## GitHub Actions / ZAP

Скопируй содержимое `lab5_security` в корень своего репозитория, включая
папку `.github`. Workflow запускается при push и pull_request в `main`.
Он выполняет pytest, Bandit, запускает API с отдельной временной базой,
проверяет готовность, запускает Docker-контейнер ZAP и загружает отчёты.
ZAP получает административный токен через настройку подстановки заголовка
Authorization. Команда сканирования приведена в workflow.

Конфигурация Docker `--network host` и адрес `127.0.0.1` рассчитаны на
Linux, в том числе Ubuntu-runner GitHub Actions. На Windows в Docker Desktop
нужно адаптировать сетевой адрес и `servers.url` в OpenAPI.

Проверки ZAP и удалённый GitHub Actions здесь не запускались: в среде
подготовки отсутствовал Docker и не был предоставлен репозиторий. Их
результатов в архиве нет. Код ZAP 0 означает успех, 1 — FAIL, 2 — WARN,
3 — ошибку запуска. Workflow сохраняет доступные артефакты даже при ошибке.

## Фактические локальные результаты

- pytest: 18 passed.
- Bandit для `vulnerable_app.py`: B608 (SQL Injection), B201 (Flask debug).
- Bandit для `app.py`: 0 замечаний.

Уязвимый образец предназначен только для локальной лабораторной работы.
Тесты используют временные базы, а активное сканирование CI — отдельную
базу. Не запускай уязвимый образец с реальными данными или в публичной сети.
