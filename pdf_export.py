import sys

from weasyprint import HTML


def main() -> int:
    html = sys.stdin.read()
    if not html.strip():
        print("empty html", file=sys.stderr)
        return 2
    base_url = sys.argv[1] if len(sys.argv) > 1 else None
    pdf = HTML(string=html, base_url=base_url).write_pdf()
    sys.stdout.buffer.write(pdf)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
