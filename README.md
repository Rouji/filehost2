# filehost2

Somewhat minimalistic file hosting service.

# config

via env vars, see src/settings.rs

# run

migrations:
```bash
./filehost2 migrate
```

the thing itself:
```bash
cargo run --release
```

# dev

tests:
```bash
SQLX_OFFLINE=true cargo test
```

mariadb container blah:
```bash
podman run --rm -p 3306:3306 -e MARIADB_DATABASE=filehost -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=true --cgroup-manager=cgroupfs mariadb:latest &
export DATABASE_URL=mysql://root@127.0.0.1:3306/filehost
cargo run migrate
cargo run
```

sqlx offline cache:
```bash
cargo sqlx prepare
```
