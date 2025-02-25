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
        datefmt='%d-%b-%y %H:%M:%S'
    )

    return logging.root
configureLogging()

def setLogFile(logger, file: Path):
    file.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving log to `{file.absolute()}`")
    handler = logging.FileHandler(file, "w")
    handler.formatter = logging.Formatter(fmt='%(levelname)s %(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
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
    group_name:     str
    combine:        bool

def parse_dt_arg(value):
    """Convert the created timestamp to a datetime object."""
    try:
        return datetime.strptime(value, '%Y-%m-%d')
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid date format. Use YYYY-MM-DD")

def parse_args():
    parser = argparse.ArgumentParser(description='Convert text file to detection format.')
    parser.add_argument('--min_discovered', default=datetime.min, help='Minimum discovered date for incident/victim', type=parse_dt_arg)
    parser.add_argument('--max_discovered', default=datetime.max, help='Maximum discovered date for incident/victim', type=parse_dt_arg)
    parser.add_argument('--group_name', required=False, help='Only process data related to a specific group. Default is all.')
    parser.add_argument('--combine', action='store_true', default=False, help='Should only create one bundle. setting to True will make separate bundle per group.')
    args: Args = parser.parse_args()
    if args.max_discovered:
        args.max_discovered = args.max_discovered.replace(hour=23, minute=59, second=59, microsecond=999_999)
    return args


    
def main(args: Args):
    output_path = Path('outputs/')
    with contextlib.suppress(Exception):
        shutil.rmtree(output_path)
    bundles_path = output_path / "bundles"
    bundles_path.mkdir(exist_ok=True, parents=True)
    setLogFile(logging.root, Path("logs")/f"ransomware2stix-{(datetime.now().isoformat(timespec='seconds').replace(':', '-'))}.txt")

    groups = Parser.parse_all_victims(args.min_discovered, args.max_discovered, groups=args.group_name and [args.group_name], combine_bundle=args.combine, write_fs=True)
    for group_name, parser in groups.items():
        path = bundles_path / f'ransomware2stix_bundle--{group_name}.json'
        with open(path, 'w') as f:
            fp_serialize(parser.bundle, f, indent=4)
            logging.info(f"Wrote bundle output for `{group_name}` to `{path}`")

if __name__ == '__main__':
    main(parse_args())