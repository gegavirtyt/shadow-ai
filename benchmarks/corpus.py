"""Deterministic synthetic DLP evaluation corpus.

Design (see BENCHMARK_METHODOLOGY.md for the full protocol):

* Ground truth is defined by construction: a sample is positive iff the generator
  embedded a credential (a value that grants access if leaked). Labels never depend
  on detector behaviour.
* Three splits with *disjoint* random seeds AND disjoint template pools:
  - ``development``  - used while engineering detectors and exemptions,
  - ``calibration``  - used only to choose the entropy margins,
  - ``heldout``      - evaluated once after the detector was frozen.
  Held-out templates (log lines, CSV, stack traces, curl commands, chat turns, ...)
  never appear in the other splits, so the evaluation measures generalisation to
  unseen contexts rather than memorised phrasings.
* Secrets are generated at runtime from seeded RNGs, so no secret-shaped literals are
  committed and the corpus is bit-for-bit reproducible (``manifest_sha256``).
* Samples are de-duplicated; each category contributes a fixed number of samples
  per split (stratified).
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import string
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass

ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX = "0123456789abcdef"
B32 = string.ascii_uppercase + "234567"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

SPLITS = {"development": 1101, "calibration": 2202, "heldout": 3303, "heldout2": 4404}
PER_CATEGORY = {"development": 30, "calibration": 30, "heldout": 60, "heldout2": 60}


@dataclass(frozen=True)
class Sample:
    id: str
    split: str
    category: str
    label: bool  # True = contains a credential
    text: str


def r(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# Credential generators (format-correct, synthetic)
# ---------------------------------------------------------------------------
def aws_key_id(rng):
    return rng.choice(["AKIA", "ASIA"]) + r(rng, B32, 16)


def aws_secret(rng):
    return r(rng, B64, 40)


def password(rng):
    words = ["Summer", "Falcon", "Orange", "Winter", "Rocket", "Harbor", "Velvet", "Granite", "Maple", "Copper"]
    return rng.choice(words) + rng.choice(words).lower() + str(rng.randint(10, 9999)) + rng.choice("!@#$%&*?")


SECRETS: dict[str, Callable[[random.Random], str]] = {
    "aws_access_key_id": aws_key_id,
    "aws_secret_access_key_ctx": lambda g: f"aws_secret_access_key = {aws_secret(g)}",
    "aws_session_token": lambda g: "IQoJb3JpZ2luX2Vj" + r(g, B64, g.randint(200, 400)),
    "github_classic_token": lambda g: g.choice(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) + r(g, ALNUM, 36),
    "github_fine_grained_pat": lambda g: "github_pat_" + r(g, ALNUM, 22) + "_" + r(g, ALNUM, 59),
    "gitlab_pat": lambda g: "glpat-" + r(g, B64URL, 20),
    "slack_bot_token": lambda g: f"xoxb-{r(g, string.digits, g.randint(10, 13))}-{r(g, string.digits, 13)}-{r(g, ALNUM, 24)}",
    "slack_webhook": lambda g: f"https://hooks.slack.com/services/T{r(g, B32, 8)}/B{r(g, B32, 10)}/{r(g, ALNUM, 24)}",
    "google_api_key": lambda g: "AIza" + r(g, B64URL, 35),
    "gcp_service_account_json": lambda g: json.dumps(
        {
            "type": "service_account",
            "project_id": "demo-proj",
            "private_key_id": r(g, HEX, 40),
            "client_email": "svc@demo-proj.iam.gserviceaccount.com",
        }
    ),
    "openai_api_key": lambda g: "sk-proj-" + r(g, B64URL, g.randint(48, 156)),
    "anthropic_api_key": lambda g: "sk-ant-api03-" + r(g, B64URL, 93) + "AA",
    "stripe_secret_key": lambda g: "sk_live_" + r(g, ALNUM, g.randint(24, 99)),
    "pem_private_key": lambda g: (
        f"-----BEGIN {g.choice(['RSA ', 'EC ', 'OPENSSH ', ''])}PRIVATE KEY-----\n"
        + "\n".join(r(g, B64, 64) for _ in range(3))
        + "\n-----END PRIVATE KEY-----"
    ),
    "database_url": lambda g: (
        f"{g.choice(['postgresql', 'mysql', 'mongodb+srv', 'redis', 'amqp'])}://{g.choice(['app', 'svc_ro', 'admin', 'etl'])}:"
        + r(g, ALNUM + "!$%", g.randint(12, 24))
        + f"@{g.choice(['db', 'cache', 'mq'])}-{g.randint(1, 9)}.internal:{g.choice([5432, 3306, 27017, 6379, 5672])}/{g.choice(['app', 'prod', 'events'])}"
    ),
    "keyword_hex_secret": lambda g: (
        f"{g.choice(['api_key', 'secret_key', 'auth_token', 'client_secret', 'access_token', 'API key is'])}"
        f"{g.choice([' = ', ': ', '='])}{r(g, HEX, g.choice([32, 40, 64]))}"
    ),
    "keyword_generic_secret": lambda g: (
        f"{g.choice(['api_key', 'apiKey', 'client_secret', 'token', 'secret', 'auth_token'])}"
        f"{g.choice([' = ', ': ', '='])}{r(g, ALNUM, g.randint(24, 48))}"
    ),
    "password_assignment": lambda g: (
        f"{g.choice(['password', 'PASSWORD', 'db_password', 'passwd', 'pwd'])}{g.choice([' = ', ': ', '=', ' is '])}{password(g)}"
    ),
    "bare_random_base62": lambda g: r(g, ALNUM, g.randint(28, 48)),
    "bare_random_base64_40": aws_secret,
    "bare_random_hex": lambda g: r(g, HEX, g.choice([32, 40, 64])),  # expected limitation (no context)
}


def _obfuscate(kind: str, value: str, g: random.Random) -> str:
    if kind == "b64":
        return base64.b64encode(value.encode()).decode()
    if kind == "url":
        return urllib.parse.quote(value, safe="")  # alnum values are unchanged by quoting; use double quoting
    if kind == "dblurl":
        return urllib.parse.quote(urllib.parse.quote("".join(f"%{ord(c):02X}" for c in value), safe=""), safe="")
    if kind == "hexstr":
        return value.encode().hex()
    if kind == "zw":
        return "​".join(value)
    if kind == "fullwidth":
        return "".join(chr(0xFF00 + ord(c) - 0x20) if c.isalnum() else c for c in value)
    raise AssertionError(kind)


OBFUSCATION_KINDS = ["b64", "dblurl", "hexstr", "zw", "fullwidth"]


def obfuscated_secret(g: random.Random) -> str:
    base = g.choice([aws_key_id, SECRETS["github_classic_token"], SECRETS["google_api_key"], SECRETS["slack_bot_token"]])(g)
    return _obfuscate(g.choice(OBFUSCATION_KINDS), base, g)


SECRETS["obfuscated_provider_token"] = obfuscated_secret


def ulid(g: random.Random) -> str:
    """Realistic ULID: 48-bit millisecond timestamp (2023-2026) + 80 random bits, Crockford base32."""
    ms = g.randint(1_672_531_200_000, 1_798_761_600_000)
    value = (ms << 80) | g.getrandbits(80)
    return "".join(CROCKFORD[(value >> (5 * i)) & 31] for i in reversed(range(26)))


# ---------------------------------------------------------------------------
# Benign generators (hard negatives)
# ---------------------------------------------------------------------------
TOPICS = [
    "the quarterly roadmap",
    "our Kubernetes upgrade",
    "the incident review",
    "latency regressions",
    "the onboarding guide",
    "the billing migration",
    "cache invalidation",
    "the vendor contract",
    "GDPR retention rules",
    "the load test plan",
]
VERBS = ["summarise", "review", "explain", "draft notes on", "compare options for", "list risks in", "estimate effort for"]


def pem_public(g: random.Random) -> str:
    """Well-formed public PEM block (BEGIN and END labels must agree)."""
    kind = g.choice(["PUBLIC KEY", "CERTIFICATE"])
    body = "\n".join(r(g, B64, 64) for _ in range(g.randint(1, 4)))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


def prose(g):
    return f"Please {g.choice(VERBS)} {g.choice(TOPICS)} and {g.choice(VERBS)} {g.choice(TOPICS)} for {g.choice(['Monday', 'the board', 'the team'])}."


def code_no_secret(g):
    name = g.choice(["load_config", "fetch_user", "parse_events", "retry_request", "build_index"])
    return g.choice(
        [
            f"def {name}(path):\n    with open(path) as fh:\n        return json.load(fh)",
            f"const {name} = async (id) => {{ const res = await fetch(`/api/items/${{id}}`); return res.json(); }}",
            f"api_key = os.environ['API_KEY']  # loaded at runtime in {name}",
            f'token = get_token_from_vault("{name}")',
            "password = getpass.getpass(prompt='Password: ')",
            f"for i in range({g.randint(2, 99)}):\n    total += values[i] * weight",
        ]
    )


NEGATIVES: dict[str, Callable[[random.Random], str]] = {
    "prose": prose,
    "code_without_secret": code_no_secret,
    "sha256_hex_digest": lambda g: r(g, HEX, 64),
    "sha1_git_commit": lambda g: r(g, HEX, 40),
    "md5_digest": lambda g: r(g, HEX, 32),
    "uuid": lambda g: str(uuid.UUID(int=g.getrandbits(128))),
    "ulid": lambda g: ulid(g),
    "container_image_digest": lambda g: f"ghcr.io/acme/api@sha256:{r(g, HEX, 64)}",
    "sri_integrity_hash": lambda g: f'integrity="sha384-{base64.b64encode(g.randbytes(48)).decode()}"',
    "base64_english_text": lambda g: base64.b64encode(prose(g).encode()).decode(),
    "ssh_public_key": lambda g: (
        f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{r(g, B64, 43)} {g.choice(['alice', 'ci', 'deploy'])}@host"
    ),
    "pem_public_material": lambda g: pem_public(g),
    "stripe_publishable_key": lambda g: "pk_live_" + r(g, ALNUM, g.randint(24, 99)),
    "placeholder_assignment": lambda g: g.choice(
        [
            'api_key = "<your-api-key>"',
            "OPENAI_API_KEY=${OPENAI_API_KEY}",
            "token: {{ secrets.TOKEN }}",
            "password = os.getenv('DB_PASS')",
            "client_secret: xxxxxxxxxxxxxxxx",
            "Authorization: Bearer <token>",
            "AWS_SECRET_ACCESS_KEY=your_secret_key_here",
            "password: ********",
        ]
    ),
    "placeholder_database_url": lambda g: (
        f"{g.choice(['postgresql', 'mysql'])}://{g.choice(['user', 'username'])}:{g.choice(['password', '<password>', '${DB_PASSWORD}', '****'])}@localhost:5432/app"
    ),
    "long_identifier": lambda g: "_".join(
        g.choice(["user", "account", "billing", "event", "queue", "handler", "retry", "policy", "snapshot"])
        for _ in range(g.randint(3, 6))
    ),
    "url_with_path": lambda g: (
        f"https://docs.example.com/{g.choice(['guides', 'api', 'blog'])}/{g.choice(['getting-started', 'rate-limits', 'webhooks'])}/{g.choice(['overview', 'v2', 'faq'])}"
    ),
    "version_and_numbers": lambda g: (
        f"v{g.randint(1, 9)}.{g.randint(0, 30)}.{g.randint(0, 99)}-rc{g.randint(1, 5)} built {g.randint(2020, 2026)}-{g.randint(1, 12):02d}-{g.randint(1, 28):02d}"
    ),
    "aws_arn": lambda g: f"arn:aws:iam::{r(g, string.digits, 12)}:role/{g.choice(['deploy', 'reader', 'lambda-exec'])}",
    "labelled_request_id": lambda g: f"request_id={r(g, ALNUM, 24)}",
}

# ---------------------------------------------------------------------------
# Held-out-only categories: formats the detectors were never engineered against.
# They test generalisation to *unseen formats*, not just unseen phrasings.
# ---------------------------------------------------------------------------
HELDOUT_ONLY_SECRETS: dict[str, Callable[[random.Random], str]] = {
    "unseen_npm_token": lambda g: "npm_" + r(g, ALNUM, 36),
    "unseen_digitalocean_token": lambda g: "dop_v1_" + r(g, HEX, 64),
    "unseen_sendgrid_key": lambda g: "SG." + r(g, B64URL, 22) + "." + r(g, B64URL, 43),
    "unseen_header_api_token": lambda g: f"X-Api-Token: {r(g, ALNUM, 40)}",
}
HELDOUT_ONLY_NEGATIVES: dict[str, Callable[[random.Random], str]] = {
    "unseen_nanoid_share_url": lambda g: f"https://app.example.com/s/{r(g, B64URL, 21)}",
    "unseen_npm_integrity": lambda g: f"sha512-{base64.b64encode(g.randbytes(64)).decode()}",
    "unseen_k8s_pod_name": lambda g: f"api-{r(g, HEX[:10] + 'bcdf', 10)}-{r(g, string.ascii_lowercase + string.digits, 5)}",
    "unseen_aws_request_id": lambda g: f"x-amzn-RequestId: {uuid.UUID(int=g.getrandbits(128))}",
    "unseen_git_lfs_pointer": lambda g: (
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{r(g, HEX, 64)}\nsize {g.randint(1000, 10**7)}"
    ),
}

# Second held-out split, defined AFTER the first held-out evaluation exposed a tokenizer bug
# and BEFORE this split was ever evaluated. New seed, new templates, new unseen formats; it
# deliberately excludes the first held-out's unseen categories (post-hoc fixes may target them).
HELDOUT2_ONLY_SECRETS: dict[str, Callable[[random.Random], str]] = {
    "unseen2_huggingface_token": lambda g: "hf_" + r(g, ALNUM, 34),
    "unseen2_linear_api_key": lambda g: "lin_api_" + r(g, ALNUM, 40),
    "unseen2_shopify_token": lambda g: "shpat_" + r(g, HEX, 32),
    "unseen2_azure_storage_conn": lambda g: (
        "DefaultEndpointsProtocol=https;AccountName=acmedata;AccountKey="
        + base64.b64encode(g.randbytes(64)).decode()
        + ";EndpointSuffix=core.windows.net"
    ),
}
HELDOUT2_ONLY_NEGATIVES: dict[str, Callable[[random.Random], str]] = {
    "unseen2_docker_container_id": lambda g: r(g, HEX, g.choice([12, 64])),
    "unseen2_semver_build_metadata": lambda g: (
        f"{g.randint(1, 9)}.{g.randint(0, 20)}.{g.randint(0, 50)}+build.{g.randint(20240101, 20261231)}.{r(g, HEX, 7)}"
    ),
    "unseen2_bech32_address": lambda g: "bc1q" + r(g, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", 38),
    "unseen2_drive_file_id": lambda g: "https://drive.example.com/file/d/1" + r(g, B64URL, 32) + "/view",
}

# ---------------------------------------------------------------------------
# Template pools (disjoint per split)
# ---------------------------------------------------------------------------
TEMPLATES: dict[str, list[str]] = {
    "development": [
        "Can you check why this fails? {s}",
        "Here is the config:\n{s}",
        "```\n{s}\n```",
        "export VALUE='{s}'",
        '{{"setting": "{s}"}}',
        "The value is {s} for staging.",
    ],
    "calibration": [
        "Debug this for me: {s} - it worked yesterday.",
        "config.yaml contains:\n  value: {s}",
        "> {s}\nwhy is the parser rejecting that line?",
        "set VALUE={s} && npm start",
        "<value>{s}</value>",
        "Noting {s} in the ticket.",
    ],
    "heldout": [
        "2026-11-18T10:22:31Z WARN worker-3 request failed payload={s} attempt=2",
        "id,owner,value\n42,ops,{s}\n43,dev,none",
        'Traceback (most recent call last):\n  File "app.py", line 88, in <module>\n    client.connect("{s}")\nConnectionError',
        "curl -sS https://internal.example/api -d '{s}'",
        "| key | value |\n|-----|-------|\n| primary | {s} |",
        "[service]\nendpoint = https://svc.local\nvalue = {s}",
        "User: hey, I pasted {s} into the form, is that ok?",
        "docker run -e VALUE={s} acme/app:latest",
    ],
    "heldout2": [
        'resource "aws_instance" "app" {{\n  user_data = "{s}"\n}}',
        '{{"level":"error","ts":1763460000,"msg":"auth failed","detail":"{s}"}}',
        "Hi team,\nfor the migration use {s} until Friday.\nThanks",
        '# In[3]:\nclient = Client("{s}")',
        "-- seed data: {s}\nINSERT INTO accounts VALUES (1, 'demo');",
        "+    value: {s}\n-    value: REDACTED",
        'env:\n  - name: VALUE\n    value: "{s}"',
        'func main() {{ cfg := "{s}"; run(cfg) }}',
    ],
}


def _render(template: str, payload: str) -> str:
    return template.replace("{s}", payload).replace("{{", "{").replace("}}", "}")


def generate_split(split: str) -> list[Sample]:
    rng = random.Random(SPLITS[split])
    templates = TEMPLATES[split]
    n = PER_CATEGORY[split]
    samples: list[Sample] = []
    seen: set[str] = set()
    secrets, negatives = dict(SECRETS), dict(NEGATIVES)
    if split == "heldout":
        secrets.update(HELDOUT_ONLY_SECRETS)
        negatives.update(HELDOUT_ONLY_NEGATIVES)
    if split == "heldout2":
        secrets.update(HELDOUT2_ONLY_SECRETS)
        negatives.update(HELDOUT2_ONLY_NEGATIVES)
    for label, table in ((True, secrets), (False, negatives)):
        for category in sorted(table):
            produced, attempts = 0, 0
            while produced < n and attempts < n * 20:
                attempts += 1
                text = _render(rng.choice(templates), table[category](rng))
                if text in seen:
                    continue
                seen.add(text)
                samples.append(Sample(f"{split[:3].upper()}-{category}-{produced:03d}", split, category, label, text))
                produced += 1
    return samples


def generate_corpus() -> dict[str, list[Sample]]:
    return {split: generate_split(split) for split in SPLITS}


def manifest_sha256(corpus: dict[str, list[Sample]]) -> str:
    h = hashlib.sha256()
    for split in SPLITS:
        for s in corpus[split]:
            h.update(json.dumps(asdict(s), sort_keys=True).encode())
    return h.hexdigest()


if __name__ == "__main__":
    corpus = generate_corpus()
    for split, samples in corpus.items():
        pos = sum(s.label for s in samples)
        print(f"{split:12s} n={len(samples):5d} positives={pos} negatives={len(samples) - pos}")
    print("manifest_sha256", manifest_sha256(corpus))
