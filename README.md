# Задание 4. Реализация модуля управления антивирусными сигнатурами

## Запуск

```bash
mvn spring-boot:run
```

Приложение поднимается на `https://localhost:8443`.

## Подготовка пользователей и токенов

```bash
BASE_URL="https://localhost:8443"

ADMIN_REG=$(curl -k -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_sig","password":"Admin123!","role":"ADMIN"}')

USER_REG=$(curl -k -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_sig","password":"User123!","role":"USER"}')

ADMIN_TOKENS=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_sig","password":"Admin123!"}')

USER_TOKENS=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_sig","password":"User123!"}')

ADMIN_ACCESS=$(echo "$ADMIN_TOKENS" | jq -r '.accessToken')
USER_ACCESS=$(echo "$USER_TOKENS" | jq -r '.accessToken')
```

## 1) Добавление сигнатуры

### create (успех)

```bash
CREATE_RESPONSE=$(curl -k -s -X POST "$BASE_URL/api/signatures" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Example.A",
    "firstBytesHex": "A1B2C3D4",
    "remainderHashHex": "EEFF0011AA22",
    "remainderLength": 128,
    "fileType": "exe",
    "offsetStart": 0,
    "offsetEnd": 64
  }')

echo "$CREATE_RESPONSE" | jq
SIGNATURE_ID=$(echo "$CREATE_RESPONSE" | jq -r '.id')
```

### create (ошибка, USER не может)

```bash
curl -k -i -X POST "$BASE_URL/api/signatures" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Example.Denied",
    "firstBytesHex": "A1B2",
    "remainderHashHex": "FF11",
    "remainderLength": 1,
    "fileType": "exe",
    "offsetStart": 0,
    "offsetEnd": 1
  }'
```

## 2) Обновление сигнатуры

### update (успех)

```bash
UPDATE_RESPONSE=$(curl -k -s -X PUT "$BASE_URL/api/signatures/$SIGNATURE_ID" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Example.A.Updated",
    "firstBytesHex": "A1B2C3D4",
    "remainderHashHex": "EEFF0011AA22",
    "remainderLength": 256,
    "fileType": "dll",
    "offsetStart": 4,
    "offsetEnd": 96
  }')

echo "$UPDATE_RESPONSE" | jq
```

### update (ошибка, offsetEnd < offsetStart)

```bash
curl -k -i -X PUT "$BASE_URL/api/signatures/$SIGNATURE_ID" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Bad",
    "firstBytesHex": "A1B2C3D4",
    "remainderHashHex": "EEFF0011AA22",
    "remainderLength": 256,
    "fileType": "dll",
    "offsetStart": 100,
    "offsetEnd": 10
  }'
```

## 3) Логическое удаление

### delete (успех)

```bash
DELETE_SINCE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

curl -k -i -X DELETE "$BASE_URL/api/signatures/$SIGNATURE_ID" \
  -H "Authorization: Bearer $ADMIN_ACCESS"
```

### delete (ошибка, несуществующий id)

```bash
curl -k -i -X DELETE "$BASE_URL/api/signatures/11111111-1111-1111-1111-111111111111" \
  -H "Authorization: Bearer $ADMIN_ACCESS"
```

## 4) Получение всей базы

### get all (успех, только ACTUAL)

```bash
curl -k -s "$BASE_URL/api/signatures" \
  -H "Authorization: Bearer $USER_ACCESS" | jq
```

### get all (ошибка, без токена)

```bash
curl -k -i "$BASE_URL/api/signatures"
```

## 5) Получение инкремента

### increment (успех, включает DELETED)

```bash
curl -k -s "$BASE_URL/api/signatures/increment?since=$DELETE_SINCE" \
  -H "Authorization: Bearer $USER_ACCESS" | jq
```

### increment (ошибка, нет since)

```bash
curl -k -i "$BASE_URL/api/signatures/increment" \
  -H "Authorization: Bearer $USER_ACCESS"
```

## 6) Получение по идентификаторам

### by-ids (успех)

```bash
curl -k -s -X POST "$BASE_URL/api/signatures/by-ids" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"ids\":[\"$SIGNATURE_ID\",\"11111111-1111-1111-1111-111111111111\"]}" | jq
```

### by-ids (ошибка, пустой список)

```bash
curl -k -i -X POST "$BASE_URL/api/signatures/by-ids" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"ids":[]}'
```

## 7) Получение по одному id

### get by id (успех)

```bash
curl -k -s "$BASE_URL/api/signatures/$SIGNATURE_ID" \
  -H "Authorization: Bearer $USER_ACCESS" | jq
```

### get by id (ошибка, не найдено)

```bash
curl -k -i "$BASE_URL/api/signatures/11111111-1111-1111-1111-111111111111" \
  -H "Authorization: Bearer $USER_ACCESS"
```

## 8) Получение истории по signatureId

### history (успех, ADMIN)

```bash
curl -k -s "$BASE_URL/api/signatures/$SIGNATURE_ID/history" \
  -H "Authorization: Bearer $ADMIN_ACCESS" | jq
```

### history (ошибка, USER запрещено)

```bash
curl -k -i "$BASE_URL/api/signatures/$SIGNATURE_ID/history" \
  -H "Authorization: Bearer $USER_ACCESS"
```

## 9) Получение аудита по signatureId

### audit (успех, ADMIN)

```bash
curl -k -s "$BASE_URL/api/signatures/$SIGNATURE_ID/audit" \
  -H "Authorization: Bearer $ADMIN_ACCESS" | jq
```

### audit (ошибка, USER запрещено)

```bash
curl -k -i "$BASE_URL/api/signatures/$SIGNATURE_ID/audit" \
  -H "Authorization: Bearer $USER_ACCESS"
```

## Проверка ЭЦП

Подпись хранится в `digitalSignatureBase64` и пересчитывается при:

- `POST /api/signatures`
- `PUT /api/signatures/{id}`
- `DELETE /api/signatures/{id}` (при смене `status` на `DELETED`).

Публичный ключ и сертификат для проверки:

```bash
curl -k -s "$BASE_URL/api/licenses/signature/public-key" | jq
```
