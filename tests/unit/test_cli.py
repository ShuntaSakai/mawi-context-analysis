import subprocess
import sys
from types import ModuleType

import pytest

from mawi_context.cli import build_parser, main


EXTRACT_ARGS = [
    "extract",
    "--day", "2026-04-08",
    "--target-chunk", "202604081400",
    "--packet-counts", "1", "2", "3",
    "--workers", "16",
]


@pytest.mark.parametrize(
    ("option", "values"),
    [
        ("--day", ["2026-04-08"]),
        ("--target-chunk", ["202604081400"]),
        ("--packet-counts", ["1", "2", "3"]),
        ("--workers", ["16"]),
    ],
)
def test_extract_requires_option(option, values, capsys):
    args = EXTRACT_ARGS.copy()
    start = args.index(option)
    del args[start:start + 1 + len(values)]

    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(args)

    assert error.value.code == 2
    assert option in capsys.readouterr().err


def test_aggregate_requires_dataset(capsys):
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["aggregate"])

    assert error.value.code == 2
    assert "--dataset" in capsys.readouterr().err


@pytest.mark.parametrize("workers", ["0", "-1", "1.5", "abc"])
def test_extract_rejects_invalid_workers(workers, capsys):
    args = EXTRACT_ARGS.copy()
    args[-1] = workers

    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(args)

    assert error.value.code == 2
    assert "--workers" in capsys.readouterr().err


@pytest.mark.parametrize(
    "counts", [[], ["0", "1"], ["-1", "2"], ["1", "1", "2"], ["1.5"], ["abc"]]
)
def test_extract_rejects_invalid_packet_counts(counts, capsys):
    args = EXTRACT_ARGS.copy()
    args[args.index("--packet-counts") + 1:args.index("--workers")] = counts

    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(args)

    assert error.value.code == 2
    assert "--packet-counts" in capsys.readouterr().err


def test_parse_extract():
    args = build_parser().parse_args(EXTRACT_ARGS)

    assert args.command == "extract"
    assert args.day == "2026-04-08"
    assert args.target_chunk == "202604081400"
    assert args.packet_counts == [1, 2, 3]
    assert args.workers == 16


def test_parse_aggregate():
    args = build_parser().parse_args(["aggregate", "--dataset", "/path/to/portable_dataset"])

    assert args.command == "aggregate"
    assert args.dataset == "/path/to/portable_dataset"


def test_parser_accepts_other_positive_counts_and_defers_calendar_validation():
    args = build_parser().parse_args([
        "extract", "--day", "not-a-date", "--target-chunk", "not-a-chunk",
        "--packet-counts", "4", "7", "--workers", "1",
    ])

    assert args.packet_counts == [4, 7]
    assert args.day == "not-a-date"
    assert args.target_chunk == "not-a-chunk"


@pytest.mark.parametrize("command", [[], ["extract"], ["aggregate"]])
def test_help_works_without_later_modules(command):
    # A fresh process also catches imports performed when cli.py is loaded.
    script = """
import builtins
import sys

original_import = builtins.__import__
def reject_later_modules(name, *args, **kwargs):
    if name in {"mawi_context.extraction", "mawi_context.aggregation"}:
        raise AssertionError("help must not import later-task modules")
    return original_import(name, *args, **kwargs)
builtins.__import__ = reject_later_modules

from mawi_context.cli import main
raise SystemExit(main(sys.argv[1:]))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, *command, "--help"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout
    if not command:
        assert "extract" in result.stdout
        assert "aggregate" in result.stdout


def test_main_help_exits_successfully(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    assert error.value.code == 0
    assert "extract" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("module_name", "handler_name", "argv", "command"),
    [
        ("mawi_context.extraction", "run_extract_cli", EXTRACT_ARGS, "extract"),
        ("mawi_context.aggregation", "run_aggregate_cli",
         ["aggregate", "--dataset", "/path/to/portable_dataset"], "aggregate"),
    ],
)
def test_main_dispatches_selected_command(module_name, handler_name, argv, command, monkeypatch):
    # Later tasks supply these handlers; no stub modules are written to the repo.
    module = ModuleType(module_name)
    received = []

    def handler(args):
        received.append(args)
        return 7

    setattr(module, handler_name, handler)
    monkeypatch.setitem(sys.modules, module_name, module)

    assert main(argv) == 7
    assert len(received) == 1
    assert received[0].command == command
