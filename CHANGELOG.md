# Changelog

## 0.2.1 — 2026-10-06

- Node 24 LTS (`node:24-alpine`, зафіксований digest) замість Node 20, підтримку
  якого завершено у квітні 2026;
- `npm audit fix`: усунено critical `proxy-addr` (GHSA-jqcg-44mw-7w3h) і
  moderate `qs`/`body-parser`/`express`;
- тест вимоги ДПС: CMS містить лише сертифікат підписувача, без CRL, з eContent;
- відповідність перевірено на описі API ДПС від 17.08.2026 — вимоги до підпису
  (ДСТУ 4145, CAdES-E-T, signature-time-stamp) не змінилися.

## 0.2.0 — 2026-07-14

- attached ДСТУ-4145 CAdES-E-T для online та CAdES-BES для offline;
- обов'язковий сертифікат підписувача, перевірка строку чинності й явні помилки TSP;
- криптографічно перевірений unwrap підписаних квитанцій;
- constant-time API key, канонічний base64, size/concurrency/time limits і TSP SSRF guard;
- non-root reproducible Docker image, healthcheck, graceful shutdown, CI та 9 тестів.
