# ransomware2stix

## Overview

![](docs/ransomware2stix.png)

ransomware2stix turns intelligence on Ransomware Groups and their victims into STIX 2.1 objects.





It was born from our frustration of various intelligence producers each naming the same ransomware ever-so-slightly differently.

This project is heavily inspired by MITRE ATT&CK, aiming to fill the gap in MITRE ATT&CK for ransomware specific content. Where relevant, RansomwareKB also links back the MITRE ATT&CK framework with the ultimate goal to commit the data gathered here into MITRE ATT&CK.

## Overview Structure of the data

At present the following concepts are supported;

1. Groups (STIX `intrusion-set` objects, ID in format `GXXXX`): that describe ransomware operators and groups.
3. Tools (STIX `tool` objects, ID in format `TXXXX`): that describe the Tools used by ransomware operators and groups. This is not the Ransomware itself.
4. Victims (STIX `tool` objects, ID in format `IXXXXXX`): victims infected by the ransomware


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


--min_discovered and --max_discovered
```



## Credits

* https://ransomware.live/

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