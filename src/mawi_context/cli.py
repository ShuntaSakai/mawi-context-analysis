"""Command-line contract for extraction and portable dataset aggregation."""

import argparse
from collections.abc import Sequence


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


class _UniquePacketCounts(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) != len(set(values)):
            raise argparse.ArgumentError(self, "packet counts must not contain duplicates")
        setattr(namespace, self.dest, values)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mawi-context",
        description="Extract MAWI packet context and aggregate portable datasets.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract", help="Extract a portable observation dataset")
    extract.add_argument("--day", required=True, help="Calendar day in YYYY-MM-DD format")
    extract.add_argument("--target-chunk", required=True)
    extract.add_argument(
        "--packet-counts", required=True, nargs="+", type=_positive_int,
        action=_UniquePacketCounts,
    )
    extract.add_argument("--workers", required=True, type=_positive_int)

    aggregate = commands.add_parser("aggregate", help="Aggregate a portable observation dataset")
    aggregate.add_argument("--dataset", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "extract":
        from mawi_context.extraction import run_extract_cli

        return run_extract_cli(args)

    from mawi_context.aggregation import run_aggregate_cli

    return run_aggregate_cli(args)
