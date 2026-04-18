"""Phase 5: every @app.route referenced in templates exists, every render_template
target file exists, every fetch() URL in templates hits a real route."""
import re, sys
from pathlib import Path

src = Path('app.py').read_text(encoding='utf-8')
templates_dir = Path('templates')
tmpl_files = sorted(templates_dir.glob('*.html'))

issues = []

# ── 1. Collect all @app.route endpoints ────────────────────────────────
routes = set()
for m in re.finditer(r"@app\.route\(\s*['\"]([^'\"]+)['\"]", src):
    routes.add(m.group(1))
print(f'[5.1] @app.route endpoints: {len(routes)}')

# ── 2. Collect all url_for('endpoint_name') references ─────────────────
endpoints = set()
# Endpoint names come from function names after @app.route
route_fns = re.findall(r"@app\.route\([^\n]+\)\s*(?:@[^\n]+\s*)*def\s+([a-zA-Z_][a-zA-Z_0-9]*)", src)
endpoints.update(route_fns)
print(f'[5.2] Flask endpoint functions: {len(endpoints)}')

# ── 3. render_template calls and their target files ───────────────────
render_calls = set(re.findall(r"render_template\(\s*['\"]([^'\"]+\.html)['\"]", src))
missing_tmpl = [t for t in render_calls if not (templates_dir / t).exists()]
print(f'[5.3] templates referenced via render_template: {len(render_calls)}')
if missing_tmpl:
    issues.append(f'render_template targets missing: {missing_tmpl}')

# ── 4. url_for() in templates — check the endpoint exists ─────────────
urlfor_refs = {}
for tf in tmpl_files:
    content = tf.read_text(encoding='utf-8')
    for m in re.finditer(r"url_for\(\s*['\"]([a-zA-Z_][a-zA-Z_0-9]*)['\"]", content):
        urlfor_refs.setdefault(m.group(1), []).append(tf.name)
# 'static' is Flask's built-in endpoint for /static/<path>, auto-registered.
BUILTIN_ENDPOINTS = {'static'}
missing_endpoints = [e for e in urlfor_refs
                     if e not in endpoints and e not in BUILTIN_ENDPOINTS]
print(f'[5.4] url_for() targets in templates: {len(urlfor_refs)}')
if missing_endpoints:
    print('     MISSING endpoints referenced:')
    for e in missing_endpoints:
        print(f'       - {e}  (used by {urlfor_refs[e]})')
    issues.append(f'url_for targets missing: {missing_endpoints}')

# ── 5. fetch(...) URLs — verify they match a @app.route ───────────────
fetch_urls = set()
for tf in tmpl_files:
    content = tf.read_text(encoding='utf-8')
    # Literal fetch URLs
    for m in re.finditer(r"fetch\(\s*['`]([^'`?]+)[?'`]", content):
        fetch_urls.add(m.group(1))
# Normalize: strip trailing template-variable segments
print(f'[5.5] literal fetch URLs in templates: {len(fetch_urls)}')
missing_fetch = []
for f in sorted(fetch_urls):
    # Direct match
    if f in routes: continue
    # Match with trailing segment (eg. /api/abuseipdb/ + <ip>)
    matched = False
    for r in routes:
        r_prefix = re.sub(r'<[^>]+>', '', r)
        if f.startswith(r_prefix) and r_prefix.endswith('/'):
            matched = True; break
        # Match fetch URL as route with param stripped
        if f == r_prefix.rstrip('/'): matched = True; break
    if not matched:
        missing_fetch.append(f)
if missing_fetch:
    print(f'     POTENTIAL fetch() URLs with no matching route: {missing_fetch}')

# ── 6. report ─────────────────────────────────────────────────────────
print(f'\nROUTE/TEMPLATE ISSUES: {len(issues)}')
for i in issues: print(f'  - {i}')
if missing_fetch:
    print(f'\n  Fetch-URL mismatches (may be false positives — dynamic URL construction):')
    for f in missing_fetch: print(f'    {f}')
sys.exit(1 if issues else 0)
