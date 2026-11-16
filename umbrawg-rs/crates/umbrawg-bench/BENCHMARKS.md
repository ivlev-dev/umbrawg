# Базовые замеры (короткий прогон)

Параметры: `cargo bench -p umbrawg-bench -- --sample-size 10 --measurement-time 1 --warm-up-time 1`.

| Бенчмарк | Время (медиана) |
|---|---|
| AEAD seal_in_place 1420 B | ~2.86 µs |
| AEAD open_in_place 1420 B | ~2.57 µs |
| AEAD seal_into 65535 B | ~54.0 µs |
| AEAD open_into 65535 B | ~45.6 µs |
| BLAKE2s hash 1420 B | n/a короткий прогон |
| X25519 public_key | ~63.3 µs |
| X25519 diffie_hellman | ~83.1 µs |
| obf_begin_fixed plain Initiation | ~58.2 ns |
| obf_unprotect obf Initiation | ~507.8 ns |
| obf_unprotect obf Transport | ~811.2 ns |
| GSO split_into_segments 64×1420 | ~2.54 µs |
| GSO coalesce_into 64×1420 | ~1.83 µs |
| virtio header encode | ~535 ps |
| virtio header decode | ~744 ps |
| batch 64×1420 seal_packets | ~184.3 µs |

Ограничения: измеряется чистая арифметика/память без kernel offload, GSO и UDP offload не включены; AEAD инициализирует cipher на каждый пакет согласно текущему API.
