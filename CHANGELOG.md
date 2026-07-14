# Changelog

## 0.2.0 — 2026-07-14

- attached ДСТУ-4145 CAdES-E-T для online та CAdES-BES для offline;
- обов'язковий сертифікат підписувача, перевірка строку чинності й явні помилки TSP;
- криптографічно перевірений unwrap підписаних квитанцій;
- constant-time API key, канонічний base64, size/concurrency/time limits і TSP SSRF guard;
- non-root reproducible Docker image, healthcheck, graceful shutdown, CI та 9 тестів.
