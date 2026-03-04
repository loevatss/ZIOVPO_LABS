# Задание 1

Создать Git репозиторий для серверной части проекта.
Перенести в новый репозиторий из прошлого проекта: аутентификацию (JWT access/refresh), авторизацию (ролевая модель, правила доступа), шифрование (HTTPS), подключение к БД PostgreSQL (или иной, используемой в работе реляционной БД).
Перенести переменные и секреты с репозитория РБПО, либо создать новые.
Перенести pipeline из прошлого проекта в новый, с шагами test и build.
Изучить теорию по UML-диаграммам, ознакомиться с типами диаграмм, их значениями.
Ознакомиться с теорией по ER-диаграммам.

## Запуск

```bash
mvn spring-boot:run
```

Приложение стартует на `https://localhost:8443`.

## Требования к паролю

- минимум 8 символов;
- минимум одна заглавная буква;
- минимум одна строчная буква;
- минимум одна цифра;
- минимум один спецсимвол.

## Основные endpoint-ы

### Регистрация

```bash
curl -k -X POST "https://localhost:8443/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"User123!","role":"USER"}'
```

### Логин

```bash
TOKENS=$(curl -k -s -X POST "https://localhost:8443/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"User123!"}')

ACCESS=$(echo "$TOKENS" | jq -r '.accessToken')
REFRESH=$(echo "$TOKENS" | jq -r '.refreshToken')
```

### Обновление пары токенов

```bash
curl -k -X POST "https://localhost:8443/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}"
```

### Профиль текущего пользователя

```bash
curl -k -H "Authorization: Bearer $ACCESS" \
  "https://localhost:8443/api/users/me"
```

### Проверка защищённого endpoint-а

```bash
curl -k -H "Authorization: Bearer $ACCESS" \
  "https://localhost:8443/api/system/ping"
```

### Endpoint только для ADMIN

```bash
curl -k -H "Authorization: Bearer $ACCESS" \
  "https://localhost:8443/api/system/admin"
```

### Список пользователей для ADMIN

```bash
curl -k -H "Authorization: Bearer $ACCESS" \
  "https://localhost:8443/api/users"
```

## Проверка refresh-ротации

```bash
OLD_REFRESH="$REFRESH"

TOKENS=$(curl -k -s -X POST "https://localhost:8443/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}")

REFRESH=$(echo "$TOKENS" | jq -r '.refreshToken')

curl -k -i -X POST "https://localhost:8443/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$OLD_REFRESH\"}"
```

Ожидаемо старый refresh перестаёт работать, потому что предыдущая сессия переводится в статус REFRESHED.
