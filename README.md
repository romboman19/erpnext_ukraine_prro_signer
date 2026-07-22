# ERPNext Ukraine PRRO Signer

Ізольований headless-сервіс підпису ДСТУ-4145/CAdES-E-T для ПРРО-фіскалізації
`erpnext_ua` (ERPNext → ДПС).

Репозиторій: `erpnext_ukraine_prro_signer`. Сервіс не є Frappe app і запускається
окремим контейнером у приватній мережі ERPNext.

Побудований на open-source стеку [dstucrypt](https://github.com/dstucrypt)
(`jkurwa` + `jksreader`, MIT) — **без ліцензійних бібліотек ІІТ**. Формує
attached CMS-підписи з сертифікатом підписувача: CAdES-E-T для online і
CAdES-BES для offline документів.

## Модель безпеки

- Ключ і пароль передаються **в тілі запиту** і живуть лише в памʼяті обробки —
  сервіс нічого не зберігає на диску.
- Зберігання ключів — на боці ERP (UA KEP Key в erpnext_ua: приватний файл +
  шифрований пароль, доступ лише System Manager).
- Сервіс слухає тільки внутрішню docker-мережу, авторизація через constant-time
  порівняння `x-api-key` (мінімум 32 символи).
- Канонічний base64, ліміти payload/concurrency/time, non-root контейнер і TSP
  SSRF guard захищають signer від випадкового або ворожого вводу.
- Для інтерактивного підпису токеном існує окремий
  [VilnoCheck-SignService](https://github.com/romboman19/VilnoCheck-SignService) —
  там ключ не покидає браузер. Цей сервіс — свідомий компроміс для
  автоматичної фіскалізації чеків.

## API

### `POST /api/sign`
```json
{
  "key": "<base64 контейнера: JKS / Key-6.dat / PEM>",
  "password": "пароль контейнера",
  "data": "<base64 даних для підпису>",
  "detached": false,
  "tsp": "signature",
  "cert": "<base64 сертифіката, якщо його немає в контейнері (опційно)>"
}
```
Відповідь: `{ "signature": "<base64 CMS>", "signer": { "subject_cn", "ipn", "edrpou", "not_after" } }`

Для ДПС ПРРО використовується `detached: false` (attached CMS).

**Мітка часу (`tsp`)** — рівень CAdES:
- `"signature"` (за замовчуванням) — signature-time-stamp → **CAdES-E-T**. Обовʼязково
  для **онлайн**-документів ДПС. Адреса TSP-сервера КНЕДП береться з сертифіката
  (`subjectInfoAccess`), тож окремо налаштовувати не треба.
- `false` / `"none"` — без мітки (**CAdES-BES**). Для **офлайн**-документів, де
  позначка часу не обовʼязкова, або для тестів з сертифікатами без TSP-адреси.

ДПС вимагає signature-time-stamp і забороняє content-time-stamp (підтверджено на
еталонних `.signed` прикладах ДПС).

### `POST /api/unwrap`
Криптографічно перевіряє attached CMS і лише після цього повертає content,
підписувача та signature timestamp. Ланцюг довіри КНЕДП цим endpoint не
валідується; він підтверджує цілісність CMS, а транспорт ДПС додатково
захищений TLS.

### `GET /health`
Без авторизації: `{ "status": "ok" }`.

## Запуск

```bash
docker build -t erpnext-ukraine-prro-signer .
docker run -d --restart unless-stopped --name prro-signer \
  -e API_KEY='<випадковий-секрет-мінімум-32-символи>' \
  --network frappe_default erpnext-ukraine-prro-signer
```

Порт 8080 не публікуйте на host/Internet. Доступ до signer потрібен лише backend
ERPNext. Додаткові межі налаштовуються через `KEY_MAX_BYTES`, `CERT_MAX_BYTES`,
`DATA_MAX_BYTES`, `TSP_TIMEOUT_MS`, `TSP_MAX_RESPONSE_BYTES` і
`MAX_CONCURRENT_REQUESTS`. `ALLOW_TEST_TIME=1` дозволений тільки в тестах.

## Тест

```bash
npm ci
npm test
npm audit --omit=dev --audit-level=high
```

CI також збирає Docker image. Набір перевіряє attached/detached roundtrip,
tamper detection, TSP policy, SSRF guard, HTTP authentication і canonical base64.
