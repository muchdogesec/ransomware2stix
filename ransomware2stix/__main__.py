import argparse
import contextlib
from datetime import datetime

from dataclasses import dataclass
import json
from pathlib import Path
import logging
import shutil
from stix2 import Identity
from dotenv import load_dotenv
from stix2.serialization import fp_serialize

from ransomware2stix.parser import Parser


def configureLogging():
    # Configure logging
    stream_handler = logging.StreamHandler()  # Log to stdout and stderr
    stream_handler.setLevel(logging.INFO)
    logging.basicConfig(
        level=logging.DEBUG,  # Set the desired logging level
        format=f"%(asctime)s [%(levelname)s] %(message)s",
        handlers=[stream_handler],
        datefmt="%d-%b-%y %H:%M:%S",
    )

    return logging.root


configureLogging()


def setLogFile(logger, file: Path):
    file.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving log to `{file.absolute()}`")
    handler = logging.FileHandler(file, "w")
    handler.formatter = logging.Formatter(
        fmt="%(levelname)s %(asctime)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S"
    )
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.info("=====================ransomware2stix======================")


load_dotenv()


def parse_identity(str):
    return Identity(**json.loads(str))


@dataclass
class Args:
    min_discovered: datetime
    max_discovered: datetime
    groups: list[str]


def parse_dt_arg(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DD")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert text file to detection format."
    )
    parser.add_argument(
        "--min_discovered",
        default=datetime.min,
        help="Minimum discovered date for incident/victim",
        type=parse_dt_arg,
    )
    parser.add_argument(
        "--max_discovered",
        default=datetime.max,
        help="Maximum discovered date for incident/victim",
        type=parse_dt_arg,
    )
    parser.add_argument(
        "--groups",
        required=False,
        nargs="+",
        type=str.lower,
        help="Only process data related to specific groups. Default is all.",
    )
    parser.add_argument(
        "--process_ransomnotes",
        action="store_true",
        help="Whether to process ransomnotes. Default is False.",
    )

    args: Args = parser.parse_args()
    if args.max_discovered:
        args.max_discovered = args.max_discovered.replace(
            hour=23, minute=59, second=59, microsecond=999_999
        )
    return args


def main(args: Args):
    output_path = Path("outputs/")
    with contextlib.suppress(Exception):
        shutil.rmtree(output_path)
    bundles_path = output_path / "bundles"
    bundles_path.mkdir(exist_ok=True, parents=True)
    setLogFile(
        logging.root,
        Path("logs")
        / f"ransomware2stix-{(datetime.now().isoformat(timespec='seconds').replace(':', '-'))}.txt",
    )
    for group_name, bundle in run(args):
        logging.info(f"Finished processing group {group_name}, bundle has {len(bundle.objects)} objects")
        with open(bundles_path / f"{group_name}.json", "w") as f:
            fp_serialize(bundle, f, indent=4)
            logging.info(f"Saved bundle for group {group_name} to {f.name}")

def run(args):
    parser = Parser(start_date=args.min_discovered, end_date=args.max_discovered, should_process_ransomnotes=args.process_ransomnotes)
    groups = parser.get_groups()
    groups = {group_name: group for group_name, group in groups.items() if args.groups is None or group_name.lower() in args.groups}
    for group_index, (group_name, group) in enumerate(groups.items()):
        if args.groups and group_name.lower() not in args.groups:
            continue
        logging.info(f"Processing group {group_index + 1} of {len(groups)}: {group_name}")
        parser.reset()
        parser.build_group_bundle(group)
        yield group_name, parser.bundle


if __name__ == "__main__":
    main(parse_args())
