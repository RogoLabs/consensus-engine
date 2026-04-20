#!/usr/bin/env python3
"""Generate a composite LinkedIn share image from the Consensus Engine site."""

import http.server
import threading
import socketserver
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image
import io

DOCS_DIR = Path(__file__).parent.parent / "docs"
OUTPUT_PATH = DOCS_DIR / "linkedin-share.png"
WIDTH = 1080
HEIGHT = 1350  # 4:5 portrait — max vertical space in LinkedIn feed
BG_COLOR = (248, 250, 252)  # #f8fafc light theme


def start_server():
    """Start a local HTTP server for the docs directory."""
    import functools

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(DOCS_DIR)
    )
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def capture_stats(page, base_url):
    """Capture the hero headline + stat row from the index page."""
    page.goto(f"{base_url}/index.html", wait_until="networkidle")
    page.wait_for_timeout(5000)

    # Clip the hero headline + stat row with labels (tight crop)
    screenshot_bytes = page.screenshot(
        clip={"x": 50, "y": 100, "width": 950, "height": 400}
    )
    return Image.open(io.BytesIO(screenshot_bytes))


def capture_scatter(page, base_url):
    """Capture the scatter chart from the patterns page."""
    page.goto(f"{base_url}/patterns.html", wait_until="networkidle")
    page.wait_for_timeout(6000)

    # Find the scatter chart container using xpath
    scatter_container = page.locator("xpath=//canvas[@id='scatterChart']/..").first
    if scatter_container.count() == 0:
        # Fallback: scroll down and clip the chart area
        page.evaluate("window.scrollTo(0, 600)")
        page.wait_for_timeout(1000)
        screenshot_bytes = page.screenshot(
            clip={"x": 0, "y": 0, "width": 1280, "height": 500}
        )
    else:
        scatter_container.scroll_into_view_if_needed()
        page.wait_for_timeout(1000)
        screenshot_bytes = scatter_container.screenshot()
    return Image.open(io.BytesIO(screenshot_bytes))


def composite(stats_img, scatter_img):
    """Stitch images into a stacked 4:5 portrait composite."""
    padding = 20
    gap = 10
    canvas = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)

    usable_width = WIDTH - (padding * 2)

    # Scale both images to full width first, then figure out vertical placement
    stats_ratio = usable_width / stats_img.width
    stats_resized = stats_img.resize(
        (usable_width, int(stats_img.height * stats_ratio)),
        Image.LANCZOS,
    )

    scatter_ratio = usable_width / scatter_img.width
    scatter_resized = scatter_img.resize(
        (usable_width, int(scatter_img.height * scatter_ratio)),
        Image.LANCZOS,
    )

    total_content = stats_resized.height + gap + scatter_resized.height
    # If content is taller than canvas, scale down proportionally
    if total_content > HEIGHT - (padding * 2):
        scale = (HEIGHT - (padding * 2)) / total_content
        stats_resized = stats_resized.resize(
            (int(stats_resized.width * scale), int(stats_resized.height * scale)),
            Image.LANCZOS,
        )
        scatter_resized = scatter_resized.resize(
            (int(scatter_resized.width * scale), int(scatter_resized.height * scale)),
            Image.LANCZOS,
        )
        total_content = stats_resized.height + gap + scatter_resized.height

    # Center everything vertically
    y_start = (HEIGHT - total_content) // 2
    stats_x = (WIDTH - stats_resized.width) // 2
    canvas.paste(stats_resized, (stats_x, y_start))

    scatter_x = (WIDTH - scatter_resized.width) // 2
    scatter_y = y_start + stats_resized.height + gap
    canvas.paste(scatter_resized, (scatter_x, scatter_y))

    canvas.save(OUTPUT_PATH, "PNG")
    print(f"Saved: {OUTPUT_PATH} ({WIDTH}x{HEIGHT})")


def main():
    httpd, port = start_server()
    base_url = f"http://127.0.0.1:{port}"
    print(f"Server running on {base_url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                device_scale_factor=2,
                color_scheme="light",
            )
            page = context.new_page()

            print("Capturing stats section...")
            stats_img = capture_stats(page, base_url)
            print(f"  Stats: {stats_img.size}")

            print("Capturing scatter plot...")
            scatter_img = capture_scatter(page, base_url)
            print(f"  Scatter: {scatter_img.size}")

            print("Compositing...")
            composite(stats_img, scatter_img)

            browser.close()
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
