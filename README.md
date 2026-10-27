# jwtforge

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

A world-class JWT web-auth testing tool for **authorized** penetration testing.
Offline token analysis and forging, the full catalog of known JWT attacks, and
optional live confirmation against targets you are permitted to test — with a
prioritized console / JSON / HTML report.

> **Authorized use only.** Live-target features refuse to run without an explicit
> `--authorized` flag or a `--scope-file` listing hosts you may test. Only test
> systems you own or have written permission to assess.

## Install

```bash
git clone https://github.com/Pwned007/jwtforge.git
cd jwtforge
pip install cryptography requests click rich
```

Requires Python 3.10+. Optionally `pip install gmpy2` to speed up `recover-pubkey`.

## Attack catalog

| id | attack | severity |
|----|--------|----------|
| `alg-none` | `alg:none` signature bypass (+ case variants) | critical |
| `alg-confusion` | RS/ES/PS → HS confusion (public key as HMAC secret) | critical |
| `jwk-injection` | Embedded `jwk` header self-signed key | critical |
| `jku-injection` | `jku`/`x5u` JWKS URL spoofing (bundled server) | critical |
| `x5c-injection` | `x5c` self-signed cert chain | critical |
| `psychic-signature` | ECDSA r=s=0, CVE-2022-21449 | critical |
| `kid-injection` | `kid` path-traversal / SQLi / cmd injection | high |
| `hmac-crack` | Weak HS* secret cracking (built-in + hashcat) | high |
| `claim-tamper` | Claim tampering / signature stripping | high |
| `replay-expiry` | `exp`/`nbf` validation & replay | medium |

`jwtforge list` prints these at runtime.

## Usage

```bash
# List all attacks with severity and CWE
python jwtforge.py list

# Inspect a token and flag weaknesses
python jwtforge.py decode <token>

# Forge one variant
python jwtforge.py tamper <token> --alg none --claim role=admin
python jwtforge.py tamper <token> --claim role=admin --secret <known-hmac-secret>

# Crack a weak HS* secret
python jwtforge.py crack <token> -w rockyou.txt          # built-in engine
python jwtforge.py crack <token> -w rockyou.txt --hashcat  # hashcat mode 16500 handoff

# Run one attack, print candidate tokens
python jwtforge.py attack alg-confusion <token> --public-key server_pub.pem
python jwtforge.py attack jku-injection <token> --jku-url http://attacker/jwks.json

# Host an attacker JWKS for jku/x5u attacks (prints the matching private key)
python jwtforge.py serve-jwks --port 8000 --out attacker_key.pem

# Full offline catalog + report
python jwtforge.py scan <token> --public-key server_pub.pem -w rockyou.txt \
    --html report.html --json report.json

# Full catalog WITH live confirmation (authorized targets only)
python jwtforge.py scan <token> \
    --url https://target/api --header "Authorization: Bearer {{token}}" \
    --failure-marker "Unauthorized" --authorized
```

### Acquiring the public key for algorithm confusion

Confusion attacks need the server's RSA/EC public key as the forged HMAC secret.
Three ways to get it:

```bash
# Fetch from a JWKS endpoint and print PEM + base64
python jwtforge.py jwks --url "https://target.example.com"
python jwtforge.py jwks --jwks-url "https://target.example.com/jwks.json" --out pub.pem

# Recover it from two server-issued tokens when no JWKS is exposed (sig2n GCD
# attack; RS256/384/512 only, slow for 2048-bit keys without gmpy2 installed)
python jwtforge.py recover-pubkey <TOKEN_1> <TOKEN_2> --out recovered.pem
```

`python jwtforge.py scan --url <target>` auto-fetches the JWKS itself and auto-bumps
`exp` on every forged candidate so short-lived tokens don't fail purely on expiry
(`--no-refresh-exp` to disable that). Pass `--jwks-url` to point at a non-standard
JWKS path, or `--second-token` to trigger sig2n recovery inline.

### Live targeting

Provide `--url` with a header/body template containing the `{{token}}`
placeholder, or a raw HTTP request file via `--template` (with `--url` as the
base). jwtforge captures a baseline with the real token and a rejection baseline
with a junk token, then classifies each forged candidate as **CONFIRMED**
(accepted) or not. Tune detection with `--success-marker` / `--failure-marker`.

Authorization is enforced at runtime: pass `--authorized` or a `--scope-file`
(one `host[:port]` per line).

**From a raw Burp request:** copy the request to a text file, replace the token
value with the literal placeholder `{{token}}` (a ready-made example is in
[`examples/burp_request.txt`](examples/burp_request.txt)), then:

```bash
python jwtforge.py scan <original-token> \
    --template request.txt --url https://target.example.com \
    --failure-marker "Unauthorized" --authorized \
    --html report.html --json report.json
```

CRLF line endings, POST bodies, and a stale `Content-Length` are handled
automatically. Add `--proxy http://127.0.0.1:8080` to watch the traffic in Burp,
and `--insecure` for HTTPS through a proxy or with a self-signed cert.

## Architecture

Everything lives in a single file (`jwtforge.py`) in sections:

```
CORE        JWT model, base64url, sign/verify, key helpers, sig2n recovery
ATTACKS     One class per attack: alg-none, alg-confusion, jwk/jku/x5c injection,
            psychic-signature, kid-injection, hmac-crack, claim-tamper, replay-expiry
SCANNER     Orchestration, Finding / CandidateResult objects
LIVE        HTTP client, oracle (accept/reject classifier), scope guard
JWKS SERVER Attacker-controlled JWKS host (stdlib only, no extra deps)
REPORT      Console (rich), JSON, HTML
CLI         click commands
```

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.
