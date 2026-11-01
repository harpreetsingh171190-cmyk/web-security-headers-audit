from webheaders.checks import check_content_type_options, check_csp, check_hsts, evaluate


def test_hsts_missing_fails():
    assert check_hsts({}).status == "fail"


def test_hsts_present_passes():
    assert check_hsts({"strict-transport-security": "max-age=31536000"}).status == "pass"


def test_csp_unsafe_inline_warns():
    assert check_csp({"content-security-policy": "script-src 'self' 'unsafe-inline'"}).status == "warn"


def test_nosniff_is_case_insensitive():
    assert check_content_type_options({"x-content-type-options": "NoSniff"}).status == "pass"


def test_evaluate_all_good_headers_gives_grade_a():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Server": "nginx",
    }
    report = evaluate("https://example.com", headers)
    assert report.score == 100
    assert report.grade == "A"


def test_evaluate_no_headers_is_grade_f():
    assert evaluate("https://example.com", {}).grade == "F"
