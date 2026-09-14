import pytest
from pathlib import Path
from auto_remediate.cli import main


def test_cli_scan_clean_dir(tmp_path: Path, capsys):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("print('hello world')\n", encoding="utf-8")

    ret = main(["scan", str(tmp_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Escaneo DevSecOps" in captured.out
    assert "Total hallazgos detectados" in captured.out


def test_cli_triage(tmp_path: Path, capsys):
    code_file = tmp_path / "vuln.py"
    code_file.write_text('import subprocess\nsubprocess.run("dir", shell=True)\n', encoding="utf-8")

    ret = main(["triage", str(tmp_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Triaje y Clasificación" in captured.out


def test_cli_fix_dry_run_and_apply(tmp_path: Path, capsys):
    target_file = tmp_path / "app_req.py"
    target_file.write_text('import requests\nrequests.get("https://example.com")\n', encoding="utf-8")

    # Dry-run
    ret_dry = main(["fix", str(tmp_path)])
    assert ret_dry == 0
    captured_dry = capsys.readouterr()
    assert "Modo Dry-Run" in captured_dry.out

    # Apply
    ret_apply = main(["fix", str(tmp_path), "--apply"])
    assert ret_apply == 0
    captured_apply = capsys.readouterr()
    assert "Resumen: 1 parches aplicados exitosamente" in captured_apply.out or "Resumen:" in captured_apply.out

    # El archivo debe tener timeout
    content = target_file.read_text(encoding="utf-8")
    assert "timeout=10.0" in content


def test_cli_report(tmp_path: Path, capsys):
    rep_path = tmp_path / "report.md"
    ret = main(["report", str(tmp_path), "-o", str(rep_path)])
    assert ret == 0
    assert rep_path.exists()
    assert "Informe Ejecutivo de Auto-Remediación DevSecOps" in rep_path.read_text(encoding="utf-8")


def test_cli_missing_args():
    with pytest.raises(SystemExit):
        main([])


def test_cli_target_not_found(capsys):
    ret = main(["scan", "/non/existent/path/xyz_123"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Ruta no encontrada" in captured.err
