import argparse
from datetime import datetime

from dataclasses import dataclass
import json
from pathlib import Path
import logging
from stix2 import Identity
from dotenv import load_dotenv
from stix2.serialization import fp_serialize

from ransomware2stix.parser import parse_victims

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
    logger.info("=====================txt2stix======================")

load_dotenv()

def parse_identity(str):
    return Identity(**json.loads(str))

@dataclass
class Args:
    min_discovered: datetime
    max_discovered: datetime

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
    args: Args = parser.parse_args()
    return args


    
def main(args: Args):
    output_path = Path('output/ransomware2stix-bundle.json')
    output_path.parent.mkdir(exist_ok=True, parents=True)
    setLogFile(logging.root, Path(f"output/ransomware2stix-log.txt"))
    p = parse_victims(args.min_discovered, args.max_discovered)
    with open(output_path, 'w') as f:
        fp_serialize(p.parsed_objects, f, indent=4)
    logging.info(f"Wrote bundle output to `{output_path}`")

if __name__ == '__main__':
    main(parse_args())