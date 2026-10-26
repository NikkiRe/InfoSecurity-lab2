#!/usr/bin/env python3
# Рендер терминальных скриншотов для отчёта ЛР2 из results.json
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from html import escape
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
SHOTS = ROOT / "screenshots"
CHROME = str(Path.home() / "Library/Caches/ms-playwright/chromium-1208/"
             "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
             "Google Chrome for Testing")

data = json.loads((ROOT / "results.json").read_text())
checked = datetime.fromisoformat(data["checked_at"]).astimezone(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M МСК")
passed = sum(data["checks"].values())
total = len(data["checks"])
vuln, fixed = data["environments"]
marker = "LAB2-CVE-2021-43798-CONTROLLED-FILE"
attack = vuln["traversal"]["path"]


def first_line(body):
    return body.splitlines()[0][:70] if body.strip() else ""


verify_lines = [
    "$ python3 lab2/demo.py",
    json.dumps({"cve": data["cve"], "all_passed": data["all_passed"], "checks": data["checks"]}, ensure_ascii=False, indent=2),
    "",
    f"Checks passed: {passed}/{total}",
    f"Timestamp: {checked}",
]

cmp_lines = [
    "CVE-2021-43798 - DIRECTORY TRAVERSAL (read /tmp/lab2-proof.txt)",
    "",
    f"GET {attack}",
    "",
    f"vulnerable - Grafana {vuln['version']} - 127.0.0.1:{vuln['port']}",
    f"=> HTTP {vuln['traversal']['status']} | {first_line(vuln['traversal']['body'])}",
    "",
    f"fixed - Grafana {fixed['version']} - 127.0.0.1:{fixed['port']}",
    f"=> HTTP {fixed['traversal']['status']} | {first_line(fixed['traversal']['body'])}",
]

TPL = """<!doctype html><html><head><meta charset='utf-8'><style>
 body{{margin:0;background:transparent}}
 .term{{width:900px;background:#0c0f14;border:1px solid #2b3240;border-radius:10px;overflow:hidden;
        font-family:'SF Mono',Menlo,Consolas,monospace}}
 .bar{{background:#1c2230;padding:9px 14px;display:flex;align-items:center;gap:8px}}
 .dot{{width:12px;height:12px;border-radius:50%}}
 .r{{background:#ff5f56}}.y{{background:#ffbd2e}}.g{{background:#27c93f}}
 .ttl{{color:#9aa4b2;font:12px system-ui;margin-left:10px}}
 pre{{margin:0;padding:16px 18px;color:#d7dde6;font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-all}}
 .ok{{color:#51d88a}} .warn{{color:#f6c453}}
</style></head><body>
 <div class='term'>
  <div class='bar'><span class='dot r'></span><span class='dot y'></span><span class='dot g'></span>
   <span class='ttl'>{title}</span></div>
  <pre>{body}</pre>
 </div>
</body></html>"""


def colorize(text):
    text = escape(text)
    text = text.replace("true", "<span class='ok'>true</span>")
    text = text.replace(f"{passed}/{total}", f"<span class='ok'>{passed}/{total}</span>")
    text = text.replace(f"HTTP {vuln['traversal']['status']} | {escape(marker)}", f"<span class='warn'>HTTP {vuln['traversal']['status']}</span> | <span class='warn'>{escape(marker)}</span>")
    text = text.replace(f"HTTP {fixed['traversal']['status']}", f"<span class='ok'>HTTP {fixed['traversal']['status']}</span>")
    return text


def render(page, lines, title, outfile):
    html = TPL.format(title=escape(title), body=colorize("\n".join(lines)))
    page.set_content(html)
    page.wait_for_timeout(200)
    page.locator(".term").screenshot(path=str(SHOTS / outfile))
    print("saved", outfile)


def main():
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=CHROME, headless=True)
        page = b.new_page(viewport={"width": 960, "height": 700}, device_scale_factor=2)
        render(page, verify_lines, "verify.py - повторная проверка CVE-2021-43798", "04-recheck-terminal.png")
        render(page, cmp_lines, "Сравнение: Grafana 8.3.0 (уязвимый) и 8.3.1 (исправленный)", "05-http-comparison-terminal.png")
        b.close()


if __name__ == "__main__":
    main()
