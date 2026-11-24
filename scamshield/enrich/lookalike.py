"""Brand lookalike detection for certificate names."""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

import tldextract

from scamshield.config import CONFIG_DIR, _yaml
from scamshield.contracts import Brand

_ICANN = tldextract.TLDExtract(
    suffix_list_urls=(), include_psl_private_domains=False
)  # ewp.live is a private suffix: position must see ewp.live as the registrable
FACT_KEYS = (
    "brand",
    "keyword",
    "label",
    "score",
    "method",
    "position",
    "restricted_zone",
    "context",
    "context_words",
    "mode",
    "tld",
    "lure",
    "dev_label",
)


def fact_value(hit: dict) -> dict:
    """The part of a match() hit stored as the `lookalike` fact (scoring reads method, position, context from it)."""
    return {key: hit[key] for key in FACT_KEYS if key in hit}


_GLYPHS = str.maketrans("10345", "loeas")
_CONFUSABLES = str.maketrans("аеорсху", "aeopcxy")  # Cyrillic look-alikes of Latin letters


@lru_cache(maxsize=1)
def _scoring() -> dict:
    return _yaml(CONFIG_DIR / "scoring.yaml")


def _cfg() -> dict:
    return _scoring()["lookalike"]


def _distance(left: str, right: str) -> int:
    row = list(range(len(right) + 1))
    for i, a in enumerate(left, 1):
        next_row = [i]
        for j, b in enumerate(right, 1):
            next_row.append(min(next_row[-1] + 1, row[j] + 1, row[j - 1] + (a != b)))
        row = next_row
    return row[-1]


def _fold(fqdn: str) -> str:
    """Lowercase, strip `*.`, decode punycode labels, drop accents, map Cyrillic look-alikes."""
    labels = []
    for label in fqdn.lower().removeprefix("*.").rstrip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        decomposed = unicodedata.normalize("NFKD", label.translate(_CONFUSABLES))
        labels.append("".join(ch for ch in decomposed if not unicodedata.combining(ch)))
    return ".".join(labels)


_MACHINE_ID = re.compile(r"(?=[0-9a-f]*[0-9])[0-9a-f]+")  # hex with a digit: UUID/hash pieces, not words


def _normalise(text: str) -> str:
    """Homoglyph fold; machine-id pieces (pure hex with a digit) stay as-is so "4dcb" never becomes brand "adcb"."""
    parts = re.split(r"([-_.]+)", text)
    return "".join(p if _MACHINE_ID.fullmatch(p) else _fold_rn(p.translate(_GLYPHS)).replace("vv", "w") for p in parts)


def _fold_rn(text: str) -> str:
    """ "rn" -> "m", except an "rn" touching a real word from homoglyph_word_exceptions ("career" + "news" is no "careem")."""
    words = _cfg()["homoglyph_word_exceptions"]
    spans = [m.span() for m in re.finditer("|".join(map(re.escape, words)), text)]
    return re.sub(
        "rn", lambda m: m.group() if any(m.start() < end and start < m.end() for start, end in spans) else "m", text
    )


_HEX = re.compile(r"[0-9a-f]+")


def _drop_id_pieces(label: str) -> str:
    """A label with 2+ machine-id pieces (UUID, hash) is an identifier: its pure-hex pieces are not words.
    Without this, "1d3a7ce1-adcb-4dca-…" matches brand keyword "adcb" (seen in a live CT run)."""
    parts = [p for p in re.split(r"[-_]+", label) if p]
    if sum(bool(_MACHINE_ID.fullmatch(p)) for p in parts) < 2:
        return label
    return "-".join(p for p in parts if not _HEX.fullmatch(p))


def is_regional_official(fqdn: str, brands: list[Brand]) -> bool:
    """The registrable label equals the label of an official domain, on a country-code suffix outside the UAE (adcb.com.eg, aramex.com.au).
    Generic TLDs (top, xyz, online) never qualify, nor cheap country TLDs from regional_denied_tlds."""
    extracted = _ICANN(fqdn.lower().rstrip("."))
    zone, _, tld = extracted.suffix.rpartition(".")
    if (
        len(tld) != 2
        or tld == "ae"
        or tld in _scoring()["regional_denied_tlds"]
        or zone.split(".")[0] in _scoring()["restricted_foreign_zones"]
        or extracted.suffix in _scoring()["restricted_foreign_suffixes"]
    ):
        return False
    return extracted.domain in {_ICANN(d).domain for brand in brands for d in brand.official_domains}


def _platform_slot(labels: list[str]) -> int | None:
    """Index of the project slot (label left of a hosting-platform suffix), None if the host is not on a platform."""
    host = ".".join(labels)
    suffix = max((s for s in _scoring()["hosting_platforms"] if host.endswith(f".{s}")), key=len, default=None)
    return len(labels) - len(suffix.split(".")) - 1 if suffix else None


def _zone(labels: list[str]) -> tuple[int, bool]:
    """(index of the registrable label, registrable sits under a restricted foreign zone such as ac.bd)."""
    suffix = [part for part in _ICANN(".".join(labels)).suffix.split(".") if part]
    restricted = (
        len(suffix) > 1
        and suffix[-1] != "ae"
        and (
            suffix[0] in _scoring()["restricted_foreign_zones"]
            or ".".join(suffix) in _scoring()["restricted_foreign_suffixes"]
        )
    )
    return max(len(labels) - len(suffix) - 1, 0), restricted


def _split(label: str) -> list[str]:
    return [part for part in re.split(r"[-_]+", label) if part]


def _under(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in domains)


def _unproxy(host: str) -> str:
    """The real host behind a Microsoft Defender for Cloud Apps session proxy: uaepass.ae.mcas.ms is uaepass.ae, mofa.gov.tw.mcas.ms is mofa.gov.tw."""
    host = host.lower().rstrip(".")
    for suffix in _scoring()["microsoft_proxy_suffixes"]:
        if host.endswith(f".{suffix}"):
            return host.removesuffix(f".{suffix}")
    return host


def is_official(host: str, brands: list[Brand]) -> bool:
    """An official domain, or its reflection under a Microsoft Defender for Cloud Apps session proxy (uaepass.ae.mcas.ms is uaepass.ae)."""
    return any(_under(_unproxy(host), brand.official_domains) for brand in brands)


def _clean_in(label: str, keyword: str) -> bool:
    """Some occurrence of keyword in label is not crossed by an ordinary word listed for that keyword in embedded_word_exceptions ("careem" in care+email is crossed by "email")."""
    spans = [
        m.span()
        for word in _cfg().get("embedded_word_exceptions", {}).get(keyword, [])
        for m in re.finditer(re.escape(word), label)
    ]
    for m in re.finditer(f"(?={re.escape(keyword)})", label):
        start, end = m.start(), m.start() + len(keyword)
        if not any(a < end and start < b and (a < start or b > end) for a, b in spans):
            return True
    return False


def match(fqdn: str, brands: list[Brand], mode: str = "ct", url_path: str | None = None) -> dict | None:
    """Return the first brand hit (a dict with the brand id, keyword, match method and similarity). Short keywords match only a whole token; official domains are never
    candidates. mode="feed" (already phishing-listed names) relaxes the context rule for <= 3-char keywords, see 1.4."""
    raw_labels = fqdn.lower().removeprefix("*.").rstrip(".").split(".")
    if is_official(".".join(raw_labels), brands):  # raw, not folded: xn--tisalat-9xa.com (étisalat) is no etisalat.com
        return None
    raw_labels = _unproxy(".".join(raw_labels)).split(
        "."
    )  # a page seen through the Defender proxy is judged as its real host (mofa.gov.tw.mcas.ms)
    fqdn = _fold(".".join(raw_labels))
    cfg = _cfg()
    labels = [_drop_id_pieces(label) for label in fqdn.split(".")]
    label_tokens = [_split(label) for label in labels]
    tokens = {part for parts in label_tokens for part in parts}
    norm_label_tokens = [[_normalise(t) for t in parts] for parts in label_tokens]
    norm_labels = [_normalise(label) for label in labels]
    slot = _platform_slot(labels)
    # the project slot never counts for short keywords; the TLD never counts as context: "ae" in du.ac.ae is the country
    short_range = range(len(labels)) if slot is None else range(slot)
    context_tokens = {part for parts in label_tokens[:-1] for part in parts}
    context_words = sorted(context_tokens & set(_scoring()["lookalike_context"]))
    global_brands = set(_scoring()["lookalike_global_brands"])
    has_uae = labels[-1] == "ae" or bool(context_tokens & set(_scoring()["lookalike_uae_context"]))

    def result(brand, keyword, label, index, method, score, context=None):
        reg_index, restricted = _zone(labels)  # only for hits: tldextract on every name would slow the CT stream
        if raw_labels[index].startswith("xn--"):
            method = "idn"
        elif method == "token" and not raw_labels[index].isascii():
            method = "homoglyph"
        if slot is not None:
            position = "platform_label" if index == slot else "subdomain"
        else:
            position = "registrable" if index == reg_index else "subdomain"
        # a dev/staging word in the subdomain part of an unrelated site (beta-etisalat.ipixsolutions.net): likely a vendor's test copy
        dev = (
            sorted({t for parts in label_tokens[:reg_index] for t in parts} & set(cfg.get("dev_labels", [])))
            if position == "subdomain" and slot is None
            else []
        )
        return {
            "brand": brand.id,
            "official": brand.official_domains[0],
            "keyword": keyword,
            "label": label,
            "score": score,
            "method": method,
            "position": position,
            "restricted_zone": restricted,
            "context": context or ("name" if context_words else "none"),
            "context_words": context_words,
            "tokens": sorted(tokens),
            "mode": mode,
            **({"dev_label": dev[0]} if dev else {}),
        }

    for brand in brands:
        if brand.id in global_brands and not has_uae:
            continue
        if any(exclude in tokens for exclude in brand.exclude_tokens):
            continue
        for keyword in brand.keywords:
            if keyword in cfg["context_required_keywords"]:
                if (
                    context_words
                    or context_tokens & set(_scoring()["lookalike_uae_context"])
                    or _names_operator(brand, keyword, context_tokens)
                ):
                    for i, parts in enumerate(label_tokens):
                        if keyword in parts or keyword in norm_label_tokens[i]:
                            return result(brand, keyword, keyword, i, "token" if keyword in parts else "homoglyph", 1.0)
                continue
            if len(keyword) <= cfg["short_keyword_max_len"]:
                if len(keyword) <= cfg["context_keyword_max_len"]:
                    for i in short_range:
                        if _has_context_hit(context_words, keyword, label_tokens[i], norm_label_tokens[i]):
                            return result(
                                brand, keyword, keyword, i, "token" if keyword in label_tokens[i] else "homoglyph", 1.0
                            )
                    if mode == "feed" and not context_words and keyword in labels:
                        reg_index, restricted = _zone(labels)
                        hit = None if restricted else _feed_relaxed(brand, keyword, labels, slot, reg_index, url_path)
                        if hit:
                            return result(brand, keyword, keyword, hit[0], "token", 1.0, hit[1])
                    continue
                for i, parts in enumerate(label_tokens):
                    if keyword in parts or keyword in norm_label_tokens[i]:
                        return result(brand, keyword, keyword, i, "token" if keyword in parts else "homoglyph", 1.0)
                continue
            for i in range(len(labels)):
                if keyword in labels[i] and _clean_in(labels[i], keyword):
                    return result(brand, keyword, labels[i], i, "token", 1.0)
                if keyword in norm_labels[i] and _clean_in(norm_labels[i], keyword):
                    return result(brand, keyword, norm_labels[i], i, "homoglyph", 1.0)
            threshold = 1 if len(keyword) <= cfg["edit1_max_len"] else 2
            for i, parts in enumerate(norm_label_tokens):
                for raw, label in zip(label_tokens[i], parts, strict=False):
                    if abs(len(label) - len(keyword)) <= threshold and (
                        _distance(label, keyword) <= threshold or _typo_squat(label, keyword, cfg)
                    ):
                        # a fold that changed the token (e1isalat -> elisalat) is the homoglyph trick, scored as an edit-distance hit
                        return result(
                            brand,
                            keyword,
                            label,
                            i,
                            "edit-distance" if raw == label else "homoglyph",
                            cfg["edit_score"],
                        )
    return None


def path_match(fqdn: str, brands: list[Brand], url_path: str) -> dict | None:
    """Feed-mode hit for a brand named only in the URL path (dwu6.top/rta/pay): the keyword is a whole path token; a <= 3-char keyword also needs
    a context word (pay, fine, ...) in the path. Official hosts, excluded tokens and global brands without a UAE token never hit."""
    host = fqdn.lower().rstrip(".")
    words = {w for w in re.split(r"[^a-z0-9]+", url_path.lower()) if w}
    if is_official(host, brands):
        return None
    cfg = _cfg()
    context = sorted(words & set(_scoring()["lookalike_context"]))
    for brand in brands:
        if (
            brand.id in _scoring()["lookalike_global_brands"] and not words & set(_scoring()["lookalike_uae_context"])
        ) or words & set(brand.exclude_tokens):
            continue
        for keyword in brand.keywords:
            if keyword in words and (len(keyword) > cfg["context_keyword_max_len"] or context):
                return {
                    "brand": brand.id,
                    "official": brand.official_domains[0],
                    "keyword": keyword,
                    "label": keyword,
                    "score": 1.0,
                    "method": "token",
                    "position": "path",
                    "restricted_zone": False,
                    "context": "url_path",
                    "context_words": context,
                    "tokens": sorted(words),
                    "mode": "feed",
                }
    return None


def _typo_squat(label: str, keyword: str, cfg: dict) -> bool:
    """Long keyword (dubaipolice) with a mangled tail (dubaipoit, dubaipoliauey): same prefix, edit distance scaled to the length."""
    prefix = cfg["typo_prefix_len"]
    return (
        len(keyword) >= cfg["typo_min_keyword_len"]
        and label[:prefix] == keyword[:prefix]
        and _distance(label, keyword) <= int(len(keyword) * cfg["typo_edit_ratio"])
    )


def _random_looking(root: str, run_max: int, letters_min_len: int) -> bool:
    if any(c.isdigit() for c in root):
        return True
    # y counts as a vowel (flynn, lynx); letter-only names under letters_min_len are mostly acronyms (kfc, kfcs)
    return len(root) >= letters_min_len and bool(
        re.search(rf"[^aeiouy]{{{run_max + 1}}}|[aeiouy]{{{run_max + 1}}}", root)
    )


def smishing_pattern(fqdn: str) -> dict | None:
    """UAE smishing shape without a brand: a UAE word token, a cheap TLD and a short random-looking registrable name. Fact shape like match()."""
    cfg = _scoring()["smishing"]
    labels = _fold(fqdn).split(".")
    if len(labels) < 2 or labels[-1] not in cfg["tlds"]:
        return None
    root, subs = labels[-2], labels[:-2]
    root_tokens = _split(root)
    words = cfg["words"]
    found = sorted({t for label in subs for t in _split(label)} & set(words) | set(root_tokens) & set(words))
    others = [t for t in root_tokens if t not in words]  # "uae-fine.top" has no random part: it is not this pattern
    random_part = next(
        (
            t
            for t in others
            if cfg["root_min_len"] <= len(t) <= cfg["root_max_len"]
            and t not in cfg["common_words"]
            and _random_looking(t, cfg["run_max"], cfg["letters_min_len"])
        ),
        None,
    )
    if not found or not random_part:
        return None
    return {
        "brand": None,
        "keyword": found[0],
        "label": random_part,
        "score": 1.0,
        "method": "smishing_pattern",
        "position": "registrable",
        "restricted_zone": False,
        "context": "name",
        "context_words": found,
        "mode": "ct",
        "tld": labels[-1],
    }


def generic_name(fqdn: str, scoring: dict, host_suffixes: list[str]) -> dict | None:
    """Brandless suspicious name: a lure word and a cheap TLD, not a service subdomain or a hosting platform. Fact shape like match(); `apex` is the
    registrable domain to queue (www., precert/cert and SAN repeats of one site all become one candidate).
    Domain age is not known from CT without a request, so a cheap TLD is the only second signal."""
    cfg = scoring.get("generic")
    labels = fqdn.lower().removeprefix("*.").rstrip(".").split(".")
    if not cfg or len(labels) < 2 or labels[-1] not in scoring["smishing"]["tlds"] or labels[0] in cfg["skip_labels"]:
        return None
    host = ".".join(labels)
    if any(host.endswith(f".{s}") for s in [*scoring["hosting_platforms"], *host_suffixes]):
        return None
    extracted = _ICANN(host)
    if not extracted.domain or not extracted.suffix:
        return None
    apex = f"{extracted.domain}.{extracted.suffix}"
    subs = [label for label in extracted.subdomain.split(".") if label and label not in cfg["apex_labels"]]
    tokens = {t for label in [*subs, extracted.domain] for t in re.split(r"[^a-z0-9]+", label)}
    strong, weak = sorted(tokens & set(cfg["lure_strong"])), sorted(tokens & set(cfg["lure_weak"]))
    if not strong and not (
        weak and (len(weak) > 1 or "-" in extracted.domain or any(c.isdigit() for c in extracted.domain))
    ):
        return None
    return {
        "brand": None,
        "label": extracted.domain,
        "score": 1.0,
        "method": "generic_name",
        "restricted_zone": False,
        "context": "name",
        "context_words": [],
        "mode": "generic",
        "tld": labels[-1],
        "lure": (strong or weak)[0],
        "apex": apex,
        "host": ".".join([*subs, apex]),
    }  # what to queue: the lure may sit in a subdomain (login.x.top), the page is there, not on x.top


def _names_operator(brand: Brand, keyword: str, context_tokens: set[str]) -> bool:
    """A token (mis)spelling the brand's other official label is context for a common-word keyword: darb-qmobilitya.com, darb.qmobilits.top (Q Mobility runs Darb)."""
    others = {_ICANN(d).domain for d in brand.official_domains} - {keyword}
    return any(
        len(o) >= 6 and abs(len(t) - len(o)) <= 2 and _distance(t, o) <= 2 for o in others for t in context_tokens
    )


def _has_context_hit(context_words: list[str], keyword: str, parts: list[str], norm_parts: list[str]) -> bool:
    return bool(context_words) and (keyword in parts or keyword in norm_parts)


def _feed_relaxed(
    brand: Brand, keyword: str, labels: list[str], slot: int | None, reg_index: int, url_path: str | None
):
    """Feed-mode hit for a <= 3-char keyword with no context word in the name: (label index, context) or None."""
    for i, label in enumerate(labels[:reg_index]):
        if label == keyword and i != slot:
            return i, "none"
    if labels[reg_index] == keyword and slot is None and url_path:
        words = set(re.split(r"[^a-z0-9]+", url_path.lower()))
        long_name = {
            w for w in re.split(r"[^a-z0-9]+", brand.name.lower()) if len(w) > _cfg()["context_keyword_max_len"]
        }
        if words & (set(_scoring()["lookalike_context"]) | long_name):
            return reg_index, "url_path"
    return None
