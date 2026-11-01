from webheaders.cli import main


def test_rejects_non_http_url(capsys):
    assert main(["ftp://example.com"]) == 2
    assert "http://" in capsys.readouterr().err
