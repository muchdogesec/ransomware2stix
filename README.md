# ransomware2stix

## Overview

![](docs/ransomware2stix.png)

ransomware2stix turns ransomware intelligence on [ransomware.live](https://ransomware.live/) into STIX 2.1 objects ([consider supporting the project](https://buymeacoffee.com/ransomwarelive)).

## Install

```shell
# clone the latest code
git clone https://github.com/muchdogesec/ransomware2stix
# create a venv
cd ransomware2stix
python3 -m venv ransomware2stix-venv
source ransomware2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````

## Run

```shell
python3 -m ransomware2stix \
	--min_discovered YYYY-MM-DD \
	--max_discovered YYYY-MM-DD \
	--group_name STRING \
	--combine BOOLEAN
```

Where:

* `min_discovered` (optional, `YYYY-MM-DD`): This allows you to filter the results to only include incidents after the date entered. Default is all time.
* `max_discovered` (optional, `YYYY-MM-DD`): This allows you to filter the results to only include incidents before the date entered. Default is all time.
* `group_name` (optional): Filter the output to only include a single ransomware group. Default is all.
* `combine` (optional, boolean): The script will produce a bundle for each ransomware by dafault. Use this to create a single bundle output for all results.

The default output of this script is structured as follows;

```txt

├── output
│	├── bundles
│   │	├── GROUP_1.json
│	│	└── ...
│   └── stix2_objects
│   	├── GROUP_1
│		└── ...
...
```

### Examples

Get data for all groups in January 2025:

```shell
python3 -m ransomware2stix \
	--min_discovered 2025-01-01 \
	--max_discovered 2025-01-31
```

Get all data for clop;

```shell
python3 -m ransomware2stix \
	--group_name clop
```

Note, to get all group names you can use the following request;

```shell
curl -X 'GET' \
  'https://api.ransomware.live/v2/groups' \
  -H 'accept: application/json'
```

The `name` value in the response maps to `group_name` on the command line.

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

## Other ransomware tools we love

* https://ransomwatch.telemetry.ltd/
* https://ransomwhe.re/
* https://www.ransomlook.io/
* https://www.ransom-db.com/

## License

[Apache 2.0](/LICENSE).