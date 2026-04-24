# Задание 2

1. Реализовать структуру таблиц и связей в PostgreSQL по ER-диаграмме.
2. Реализовать операцию создания лицензии, опираясь на диаграмму последовательности.
3. Реализовать операцию активации лицензии, опираясь на диаграмму последовательности.
4. Реализовать операцию проверки лицензии, опираясь на диаграмму последовательности.
5. Реализовать операцию продления лицензии, опираясь на диаграмму последовательности.
6. Создать класс Ticket для передачи информации о лицензии клиентам. Тикет должен состоять из:
   - Текущей даты сервера
   - Времени жизни тикета
   - Даты активации лицензии
   - Даты истечения лицензии
   - Идентификатора пользователя
   - Идентификатора устройства
   - Флага блокировки лицензии

7. Создать класс TicketResponse, содержащий Ticket и ЭЦП на его основе

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

## Модуль лицензий (Задание 2)

### Подготовка пользователей и токенов

```bash
BASE_URL="https://localhost:8443"

ADMIN_REG=$(curl -k -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_lic","password":"Admin123!","role":"ADMIN"}')
USER_A_REG=$(curl -k -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_a","password":"User123!","role":"USER"}')
USER_B_REG=$(curl -k -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_b","password":"User123!","role":"USER"}')

ADMIN_ID=$(echo "$ADMIN_REG" | jq -r '.id')
USER_A_ID=$(echo "$USER_A_REG" | jq -r '.id')
USER_B_ID=$(echo "$USER_B_REG" | jq -r '.id')

ADMIN_TOKENS=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_lic","password":"Admin123!"}')
USER_A_TOKENS=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_a","password":"User123!"}')
USER_B_TOKENS=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_b","password":"User123!"}')

ADMIN_ACCESS=$(echo "$ADMIN_TOKENS" | jq -r '.accessToken')
USER_A_ACCESS=$(echo "$USER_A_TOKENS" | jq -r '.accessToken')
USER_B_ACCESS=$(echo "$USER_B_TOKENS" | jq -r '.accessToken')
```

### Каталог продуктов и типов лицензий

```bash
PRODUCTS=$(curl -k -s "$BASE_URL/api/licenses/catalog/products" \
  -H "Authorization: Bearer $ADMIN_ACCESS")
TYPES=$(curl -k -s "$BASE_URL/api/licenses/catalog/types" \
  -H "Authorization: Bearer $ADMIN_ACCESS")

echo "$PRODUCTS" | jq
echo "$TYPES" | jq

PRODUCT_ID=$(echo "$PRODUCTS" | jq -r '.[0].id')
TYPE_TRIAL_ID=$(echo "$TYPES" | jq -r '.[] | select(.name=="TRIAL") | .id' | head -n1)
```

### Создание лицензии администратором

```bash
LICENSE_A=$(curl -k -s -X POST "$BASE_URL/api/licenses" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": $PRODUCT_ID,
    \"typeId\": $TYPE_TRIAL_ID,
    \"ownerId\": $USER_A_ID,
    \"deviceCount\": 2,
    \"description\": \"License for user_a\"
  }")

echo "$LICENSE_A" | jq
KEY_A=$(echo "$LICENSE_A" | jq -r '.code')
```

### Активация лицензии владельцем (успешно)

```bash
ACTIVATE_A=$(curl -k -s -X POST "$BASE_URL/api/licenses/activate" \
  -H "Authorization: Bearer $USER_A_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"activationKey\": \"$KEY_A\",
    \"deviceName\": \"UserA-Laptop\",
    \"deviceMac\": \"AA:BB:CC:DD:EE:01\"
  }")

echo "$ACTIVATE_A" | jq
```

### Проверка лицензии на устройстве владельца (успешно)

```bash
curl -k -s -X POST "$BASE_URL/api/licenses/check" \
  -H "Authorization: Bearer $USER_A_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": $PRODUCT_ID,
    \"deviceMac\": \"AA:BB:CC:DD:EE:01\"
  }" | jq
```

### Негативный кейс: чужой пользователь активирует чужой ключ (ожидаемо 403)

```bash
curl -k -i -X POST "$BASE_URL/api/licenses/activate" \
  -H "Authorization: Bearer $USER_B_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"activationKey\": \"$KEY_A\",
    \"deviceName\": \"UserB-PC\",
    \"deviceMac\": \"AA:BB:CC:DD:EE:02\"
  }"
```

### Негативный кейс: проверка чужого устройства (ожидаемо 403)

```bash
curl -k -i -X POST "$BASE_URL/api/licenses/check" \
  -H "Authorization: Bearer $USER_B_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": $PRODUCT_ID,
    \"deviceMac\": \"AA:BB:CC:DD:EE:01\"
  }"
```

### Негативный кейс: лимит устройств (ожидаемо 409 на второй активации)

```bash
LICENSE_LIMIT=$(curl -k -s -X POST "$BASE_URL/api/licenses" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": $PRODUCT_ID,
    \"typeId\": $TYPE_TRIAL_ID,
    \"ownerId\": $USER_A_ID,
    \"deviceCount\": 1,
    \"description\": \"One-device license\"
  }")

KEY_LIMIT=$(echo "$LICENSE_LIMIT" | jq -r '.code')

curl -k -s -X POST "$BASE_URL/api/licenses/activate" \
  -H "Authorization: Bearer $USER_A_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"activationKey\": \"$KEY_LIMIT\",
    \"deviceName\": \"UserA-Phone\",
    \"deviceMac\": \"AA:BB:CC:DD:EE:03\"
  }" | jq

curl -k -i -X POST "$BASE_URL/api/licenses/activate" \
  -H "Authorization: Bearer $USER_A_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"activationKey\": \"$KEY_LIMIT\",
    \"deviceName\": \"UserA-Tablet\",
    \"deviceMac\": \"AA:BB:CC:DD:EE:04\"
  }"
```

### Продление лицензии (TRIAL, успешно при сроке <= 7 дней)

```bash
curl -k -s -X POST "$BASE_URL/api/licenses/renew" \
  -H "Authorization: Bearer $USER_A_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{
    \"activationKey\": \"$KEY_A\",
    \"deviceMac\": \"AA:BB:CC:DD:EE:01\"
  }" | jq
```

### ЭЦП тикета: получение публичного ключа сервера

```bash
curl -k -s "$BASE_URL/api/licenses/signature/public-key" | jq
```
