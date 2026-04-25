# Задание 5. Реализация бинарного API для передачи сигнатур

## Запуск

```bash
SERVER_PORT=8444 SSL_ENABLED=false mvn spring-boot:run
```

Приложение поднимается на `http://localhost:8444`.

## Подготовка пользователей и токенов

```bash
BASE_URL="http://localhost:8444"

ADMIN_REG=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_bin","password":"Admin123!","role":"ADMIN"}')

USER_REG=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_bin","password":"User123!","role":"USER"}')

ADMIN_TOKENS=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_bin","password":"Admin123!"}')

USER_TOKENS=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user_bin","password":"User123!"}')

ADMIN_ACCESS=$(echo "$ADMIN_TOKENS" | jq -r '.accessToken')
USER_ACCESS=$(echo "$USER_TOKENS" | jq -r '.accessToken')
```

## Подготовка сигнатур для бинарного API

### create signature #1 (успех)

```bash
CREATE_1=$(curl -s -X POST "$BASE_URL/api/signatures" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Binary.A",
    "firstBytesHex": "A1B2C3D4",
    "remainderHashHex": "EEFF0011AA22",
    "remainderLength": 128,
    "fileType": "exe",
    "offsetStart": 0,
    "offsetEnd": 64
  }')

echo "$CREATE_1" | jq
SIGNATURE_ID_1=$(echo "$CREATE_1" | jq -r '.id')
```

### create signature #2 (успех)

```bash
CREATE_2=$(curl -s -X POST "$BASE_URL/api/signatures" \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "threatName": "Trojan.Binary.B",
    "firstBytesHex": "CAFEBABE",
    "remainderHashHex": "010203040506",
    "remainderLength": 512,
    "fileType": "dll",
    "offsetStart": 4,
    "offsetEnd": 260
  }')

echo "$CREATE_2" | jq
SIGNATURE_ID_2=$(echo "$CREATE_2" | jq -r '.id')
```

### delete signature #2 for increment (успех)

```bash
SINCE_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
sleep 1

curl -i -s -X DELETE "$BASE_URL/api/signatures/$SIGNATURE_ID_2" \
  -H "Authorization: Bearer $ADMIN_ACCESS"
```

## Binary API: full dump

### binary full (успех)

```bash
curl -i -s "$BASE_URL/api/binary/signatures/full" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -o /tmp/lab5_full.multipart

head -n 20 /tmp/lab5_full.multipart
```

### binary full (ошибка, без токена)

```bash
curl -i -s "$BASE_URL/api/binary/signatures/full"
```

## Binary API: increment

### binary increment (успех)

```bash
curl -i -s "$BASE_URL/api/binary/signatures/increment?since=$SINCE_TS" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -o /tmp/lab5_increment.multipart

head -n 20 /tmp/lab5_increment.multipart
```

### binary increment (ошибка, без since)

```bash
curl -i -s "$BASE_URL/api/binary/signatures/increment" \
  -H "Authorization: Bearer $USER_ACCESS"
```

## Binary API: by-ids

### binary by-ids (успех)

```bash
curl -i -s -X POST "$BASE_URL/api/binary/signatures/by-ids" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"ids\":[\"$SIGNATURE_ID_1\",\"$SIGNATURE_ID_2\",\"11111111-1111-1111-1111-111111111111\"]}" \
  -o /tmp/lab5_by_ids.multipart

head -n 20 /tmp/lab5_by_ids.multipart
```

### binary by-ids (ошибка, пустой список)

```bash
curl -i -s -X POST "$BASE_URL/api/binary/signatures/by-ids" \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"ids":[]}'
```

## Проверка публичного ключа ЭЦП

```bash
curl -s "$BASE_URL/api/licenses/signature/public-key" | jq
```
