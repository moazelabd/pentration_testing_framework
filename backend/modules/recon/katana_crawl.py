"""
Web Crawling via katana - ACTIVE (crawls the target's live web servers -
only run against in-scope, authorized targets).

Feeds the live hosts found by httpx (live_200.txt preferred, falling back
to the full live_hosts.txt) to the industry-standard `katana` CLI
(github.com/projectdiscovery/katana) to discover pages, endpoints, forms
and - the main goal of this phase - endpoint URLs embedded in JavaScript.

-c/JC flag notes:
  -jc   JS crawl: parse and crawl endpoints found inside .js files
        (API routes, parameter names, secrets in source maps...)
  -d 3  crawl depth cap so the crawler cannot recurse forever

katana writes raw discovery lines to katana_urls.txt; js_extractor.py
splits out the pure .js hits afterwards.

Requires katana to be installed and on your PATH:
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
Run the Live Host Probe (httpx) first - this module only crawls hosts
that answered.
"""
import os
import subprocess
import tempfile

from modules import auth_ctx

# Must mirror the depths/flags documented in TOOLS_USED.txt.
KATANA_ARGS = ["-silent", "-jc", "-d", "3"]
KATANA_TIMEOUT = 900  # depth-3 crawling many hosts takes a while


def _read_input_urls(target_path: str):
    """Prefer live_200.txt (confirmed-working hosts), fall back to the
    full live_hosts.txt. Lines from either source are httpx-annotated
    like 'https://host [200] [Title]' - keep the bare URL only."""
    for filename, label in [("live_200.txt", "live_200.txt"),
                            ("live_hosts.txt", "live_hosts.txt")]:
        path = os.path.join(target_path, filename)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # keep the URL, drop trailing " [code] [Title] [tech]" tags
                    url = line.split(" [")[0].strip()
                    if url and "://" in url:
                        urls.append(url)
            return path, label, list(dict.fromkeys(urls))
    return None, None, []


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "katana_urls.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    input_path, source_label, urls = _read_input_urls(target_path)
    if input_path is None:
        return {
            "error": "No live_200.txt (or live_hosts.txt) found for this target - "
                     "run the Live Host Probe (httpx) first; this module crawls "
                     "only hosts that answered.",
            "status": 400,
        }
    if not urls:
        return {
            "error": f"{source_label} holds no usable URLs - httpx found no "
                     "live hosts to crawl.",
            "status": 400,
        }

    result_path = os.path.join(target_path, "katana_urls.txt")
    if os.path.isfile(result_path):
        os.remove(result_path)  # a failed crawl must not look like fresh output

    # katana needs a plain URL list - the live_host files carry httpx
    # annotations, so hand it a clean temp list instead of raw lines.
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as tf:
        tf.write("\n".join(urls))
        tf.flush()  # defensive; katana runs after the with-block closes the file
        temp_input = tf.name

    try:
        subprocess.run(
            ["katana", "-list", temp_input, *KATANA_ARGS,
             *auth_ctx.cli_args(auth_ctx.load(target_path)), "-o", result_path],
            timeout=KATANA_TIMEOUT,
            check=False,  # partial results after an interrupted crawl are still useful
        )
    except FileNotFoundError:
        return {
            "error": "katana isn't installed or isn't on your PATH. Install it with "
                     "`go install -v github.com/projectdiscovery/katana/cmd/katana@latest`, "
                     "then try again.",
            "status": 502,
        }
    except subprocess.TimeoutExpired:
        # -o may already have written partial results - keep and report them.
        partial = get_cached(target_path)
        return {
            "error": f"katana timed out after {KATANA_TIMEOUT}s at depth 3 and was stopped",
            "status": 504,
            **({"urls": partial["urls"], "count": len(partial["urls"])}
               if partial["ran"] else {}),
        }
    finally:
        try:
            os.remove(temp_input)
        except OSError:
            pass

    # Normalize: one URL per line, deduplicated and sorted.
    lines = []
    if os.path.isfile(result_path):
        with open(result_path, "r", encoding="utf-8") as f:
            lines = sorted({line.strip() for line in f if line.strip()})
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    if not lines:
        return {
            "urls": [],
            "count": 0,
            "crawled": len(urls),
            "source": source_label,
            "note": "katana ran but discovered nothing at depth 3 - the live "
                    "hosts may have no crawlable pages (SPA/API-only or 403 walls).",
        }

    forms = sum(1 for line in lines if "[form]" in line.lower())
    return {
        "urls": lines,
        "count": len(lines),
        "crawled": len(urls),
        "forms": forms,
        "source": source_label,
        "note": "Includes JS-crawl endpoints (-jc) and [form] entries. Use the "
                "JS File Extractor next to pull out the .js files.",
    }
