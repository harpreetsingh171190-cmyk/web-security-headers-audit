# web-security-headers-audit

A small Python command-line tool that checks a website's HTTP security headers and reports what is missing or weak, in JSON or HTML.

> Use only on websites you own or have explicit permission to test.

## Checks

- Strict-Transport-Security (HSTS) presence and `max-age`
- Content-Security-Policy presence and unsafe directives
- Clickjacking protection (X-Frame-Options or CSP `frame-ancestors`)
- X-Content-Type-Options set to `nosniff`
- Referrer-Policy presence and weak values
- Server header version disclosure

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
webheaders https://example.com
webheaders https://example.com --format html -o report.html
```

## Development

```bash
ruff check .
mypy src
pytest -q
```

## Roadmap

- Cookie flag checks (Secure, HttpOnly, SameSite)
- Multiple URLs from a file
- Docker image

## License

MIT. See `LICENSE`.
