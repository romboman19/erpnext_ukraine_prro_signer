# ERPNext Ukraine PRRO Signer

Ізольований headless-сервіс підпису ДСТУ-4145/CAdES-T для ПРРО-фіскалізації
`erpnext_ua` (ERPNext → ДПС).

Репозиторій: `erpnext_ukraine_prro_signer`. Сервіс не є Frappe app і запускається
окремим контейнером у приватній мережі ERPNext.

Побудований на open-source стеку [dstucrypt](https://github.com/dstucrypt)
(`jkurwa` + `jksreader`, MIT) — **без ліцензійних бібліотек ІІТ**. Формує
CMS/CAdES-BES підписи (attached/detached), які приймає фіскальний сервер ДПС.

## Модель безпеки

- Ключ і пароль передаються **в тілі запиту** і живуть лише в памʼяті обробки —
  сервіс нічого не зберігає на диску.
- Зберігання ключів — на боці ERP (UA KEP Key в erpnext_ua: приватний файл +
  шифрований пароль, доступ лише System Manager).
- Сервіс слухає тільки внутрішню docker-мережу, авторизація через `x-api-key`.
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
- `"signature"` (за замовчуванням) — signature-time-stamp → **CAdES-T**. Обовʼязково
  для **онлайн**-документів ДПС. Адреса TSP-сервера КНЕДП береться з сертифіката
  (`subjectInfoAccess`), тож окремо налаштовувати не треба.
- `false` / `"none"` — без мітки (**CAdES-BES**). Для **офлайн**-документів, де
  позначка часу не обовʼязкова, або для тестів з сертифікатами без TSP-адреси.

ДПС вимагає signature-time-stamp і забороняє content-time-stamp (підтверджено на
еталонних `.signed` прикладах ДПС).

### `POST /api/unwrap`
Розгортає attached CMS: `{ "data": "<base64>" }` → `{ "content": "<base64>" }`.
Використовується для самоперевірки.

### `GET /health`
Без авторизації: `{ "status": "ok" }`.

## Запуск

```bash
docker build -t erpnext-ukraine-prro-signer .
docker run -d --name prro-signer -e API_KEY=<секрет> --network frappe_default erpnext-ukraine-prro-signer
```

## Тест

```bash
npm install && npm test   # roundtrip на тестових ключах jkurwa
```
