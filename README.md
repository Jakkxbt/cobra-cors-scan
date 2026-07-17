# cors-scan

Find **exploitable CORS misconfigurations** on a target you are authorised to test.

It sends forged `Origin` headers and inspects `Access-Control-Allow-Origin` (ACAO) and
`Access-Control-Allow-Credentials` (ACAC) to tell a real, exploitable bug from harmless noise.

| Severity | Condition |
|----------|-----------|
| **HIGH** | Your attacker origin is reflected in ACAO **and** credentials are allowed — cross-origin cookie/session theft |
| **LOW**  | Attacker origin reflected but credentials off — cross-origin reads of unauthenticated responses only |
| **INFO** | `ACAO: *` — permissive, but browsers block `*` with credentials |
| *(none)* | Server returns its own fixed origin, or no ACAO — clean |

Origins tested: arbitrary, `null`, and prefix / suffix / substring bypasses **derived from the
target host** — catches naive `startswith` / `endswith` / `contains` origin checks, not just an
exact reflection.

Authorised use / testing only. Python 3, standard library, no dependencies.

## Run

```bash
python3 cors-scan.py https://target/          # human-readable
python3 cors-scan.py https://target/ --json   # machine-readable
```

## Lab

Two local mock servers ship with the tool so you can see it fire on a bug and stay quiet on a
locked-down server:

```bash
python3 vuln_app.py --port 18090   # reflects any Origin + credentials  → expect HIGH
python3 safe_app.py --port 18091   # fixed whitelisted origin           → expect silence

python3 cors-scan.py http://127.0.0.1:18090/   # HIGH — reflected origin with credentials
python3 cors-scan.py http://127.0.0.1:18091/   # no findings — properly locked down
```
