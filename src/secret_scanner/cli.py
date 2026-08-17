from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ignore import IgnoreRules
from .models import SEVERITY_ORDER, Severity
from .report import format_json, format_text
from .scanner import ScanOptions, scan_directory

DEFAULT_IGNORE_FILENAME = ".secretscanignore"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Varre um diretório em busca de senhas, chaves de API e tokens expostos no código.",
    )
    parser.add_argument("path", type=Path, help="Diretório (ou arquivo) a ser escaneado")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Formato do relatório (padrão: text)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Salva o relatório neste arquivo em vez de imprimir no terminal",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help=(
            "Severidade mínima que faz o comando sair com código de erro "
            "(padrão: high; 'none' sempre sai 0)"
        ),
    )
    parser.add_argument(
        "--reveal",
        action="store_true",
        help="Mostra o valor completo do segredo no relatório (por padrão, ele é ocultado/redigido)",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Desativa a detecção por entropia, usando só as regras de assinatura conhecidas",
    )
    parser.add_argument(
        "--min-entropy-length",
        type=int,
        default=20,
        help="Tamanho mínimo de string considerada na checagem de entropia (padrão: 20)",
    )
    parser.add_argument(
        "--ignore-file",
        type=Path,
        default=None,
        help=f"Arquivo de ignore a usar (padrão: {DEFAULT_IGNORE_FILENAME} na raiz escaneada, se existir)",
    )
    parser.add_argument("--no-color", action="store_true", help="Desativa cores no relatório em texto")
    return parser


def main(argv: list[str] | None = None) -> int:
    # On Windows, stdout/stderr default to the console's codepage (often
    # cp1252), not UTF-8 — printing the accented Portuguese text this CLI
    # uses would come out corrupted otherwise. reconfigure() is a no-op on
    # platforms where stdout is already UTF-8.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(argv)

    target = args.path.resolve()
    if not target.exists():
        parser.error(f"Caminho não encontrado: {target}")

    scan_root = target if target.is_dir() else target.parent
    ignore_file = args.ignore_file or (scan_root / DEFAULT_IGNORE_FILENAME)
    ignore_rules = IgnoreRules.load(ignore_file if ignore_file.exists() else None)

    options = ScanOptions(
        root=scan_root,
        ignore_rules=ignore_rules,
        use_entropy=not args.no_entropy,
        min_entropy_length=args.min_entropy_length,
    )

    findings = scan_directory(options)

    if target.is_file():
        relative = target.relative_to(scan_root).as_posix()
        findings = [finding for finding in findings if finding.file == relative]

    if args.format == "json":
        report = format_json(findings, reveal=args.reveal)
    else:
        use_color = not args.no_color and args.output is None and sys.stdout.isatty()
        report = format_text(findings, reveal=args.reveal, use_color=use_color)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Relatório salvo em {args.output}")
    else:
        print(report)

    if args.fail_on == "none":
        return 0

    threshold = SEVERITY_ORDER[Severity(args.fail_on)]
    found_above_threshold = any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings)
    return 1 if found_above_threshold else 0
