import pytest

from app import main


def test_parse_args_requires_target(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["app.main"],
    )

    with pytest.raises(SystemExit):
        main.parse_args()


def test_parse_args_accepts_target(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "app.main",
            "--target",
            "127.0.0.1",
        ],
    )

    args = main.parse_args()

    assert args.target == "127.0.0.1"
    assert args.no_ai is False


def test_parse_args_accepts_no_ai(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "app.main",
            "--target",
            "127.0.0.1",
            "--no-ai",
        ],
    )

    args = main.parse_args()

    assert args.target == "127.0.0.1"
    assert args.no_ai is True


def test_main_no_ai_skips_ai_analysis(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "app.main",
            "--target",
            "127.0.0.1",
            "--no-ai",
        ],
    )

    monkeypatch.setattr(
        main,
        "run_nmap_scan",
        lambda target: {
            "target": target,
            "return_code": 0,
            "stdout": """
            PORT      STATE SERVICE
            80/tcp    open  http
            """,
            "stderr": "",
            "success": True,
        },
    )

    monkeypatch.setattr(
        main,
        "save_json_report",
        lambda report: "reports/test_report.json",
    )

    def fail_if_called(*args, **kwargs):
        pytest.fail(
            "AI analysis should not be called when --no-ai is used."
        )

    monkeypatch.setattr(
        main,
        "run_ai_analysis",
        fail_if_called,
    )

    main.main()

    output = capsys.readouterr().out

    assert "AI analysis skipped (--no-ai)." in output
    assert "JSON report saved to: reports/test_report.json" in output


def test_main_handles_scan_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "app.main",
            "--target",
            "127.0.0.1",
            "--no-ai",
        ],
    )

    monkeypatch.setattr(
        main,
        "run_nmap_scan",
        lambda target: {
            "target": target,
            "return_code": 1,
            "stdout": "",
            "stderr": "Nmap test failure.",
            "success": False,
        },
    )

    main.main()

    output = capsys.readouterr().out

    assert "Scan failed." in output
    assert "Nmap test failure." in output