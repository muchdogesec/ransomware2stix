import contextlib
import itertools
import logging
import os
from pathlib import Path
import shutil
import uuid
from dateutil.parser import parse as dateutitl_parse_date

import requests

from ransomware2stix import retriever
from stix2 import (
    IntrusionSet,
    Relationship,
    Identity,
    Incident,
    Tool,
    AttackPattern,
    FileSystemStore,
    Bundle,
)
from stix2.utils import format_datetime, STIXdatetime, Precision
from datetime import datetime
from stix2extensions.tools import crypto2stix

NAMESPACE = uuid.UUID("7bae962c-40ae-5817-8cdc-e1b6eb4f38f5")
DEFAULT_DATE = datetime(2020, 1, 1)

RANSOMWARE_LIVE_API_KEY = os.environ['RANSOMWARE_LIVE_API_KEY']


def parse_date(date_string: str):
    return date_string and STIXdatetime(
        dateutitl_parse_date(date_string),
        precision=Precision.MILLISECOND,
    )


def get_relationship_id(source_ref, target_ref, created=None):
    id_part = f"{source_ref}+{target_ref}"
    if isinstance(created, datetime):
        id_part += "+" + format_datetime(created)
    elif isinstance(created, str):
        id_part += "+" + created
    return str(uuid.uuid5(NAMESPACE, id_part))


class GroupError(Exception):
    pass


SECTOR_MAPPING = {
    "Emergency Services": "emergency-services",
    "Government Facilities": "government",
    "Healthcare and Public Health": "healthcare",
    "Education Facilities": "education",
    "Critical Manufacturing": "manufacturing",
    "Transportation Systems": "transportation",
    "Communication": "communications",
    "Commercial Facilities": "commercial",
    "Financial": "financial-services",
    "Energy": "energy",
    "Information Technology": "technology",
    "Water and Wastewater Systems": "water",
    "Food and Agriculture": "agriculture",
    "Defense Industrial Base": "defense",
    "Chemical": "chemical",
    "Nuclear Reactors, Materials, and Waste": "nuclear",
    "Agriculture": "agriculture",
    "Aerospace": "aerospace",
    "Advertising, Marketing & Public Relations": "communications",
    "Business Services": "commercial",
    "Law Firms & Legal Services": "commercial",
    "Wholesale & Retail": "retail",
    "Manufacturing": "manufacturing",
    "Healthcare Services": "healthcare",
    "Engineering": "construction",
    "Hospitality and Tourism": "hospitality-leisure",
    "Education": "education",
    "Automotive": "automotive",
    "IT Manufacturing": "manufacturing",
    "Food & Beverages": "agriculture",
    "Energy & Utilities": "energy",
    "Internet & Telecommunication Services": "telecommunications",
    "Government": "government",
    "Transportation": "transportation",
    "Shipping & Logistics": "transportation",
    "Community, Social Services & Non-Profit Organisations": "non-profit",
    "Others": "utilities",
    "Broadcasting": "communications",
    "Not Found": None,
    "Transportation/Logistics": "transportation",
    "Healthcare": "healthcare",
    "Technology": "technology",
    "Agriculture and Food Production": "agriculture",
    "Retail": "retail",
    "Legal": "commercial",
    "Business Services, Technology": "technology",
    "Financial Services": "financial-services",
    "Consumer Services": "commercial",
    "Public Sector": "government-public-services",
    "Telecommunication": "telecommunications",
    "Construction": "construction",
    "Real Estate": "commercial",
}

TOOL_MAPPING = {
    "CredentialTheft": (
        "information-gathering",
        "T0004",
        "Credential Theft Tools",
        "There are a number of free password recovery tools available that are designed to help users recover lost or forgotten passwords stored on their own systems. These tools can extract passwords saved in web browsers, email clients, and other applications. IT professionals can use these tools to recover credentials needed for system maintenance or troubleshooting.",
    ),
    "DefenseEvasion": (
        "exploitation",
        "T0003",
        "Defense Evasion Tools",
        "Various freely available malware detection tools specialize in identifying and removing stealthy threats like rootkits. They offer capabilities such as scanning for hidden processes, files, and drivers, analyzing system memory for malicious modules, and monitoring system hooks for unauthorized modifications. These tools provide detailed insights into system internals, helping to uncover deeply embedded malware that standard antivirus programs might miss.",
    ),
    "DiscoveryEnum": (
        "information-gathering",
        "T0001",
        "Discovery and Enumeration Tools",
        "There are a number of network scanning and profiling tools available online that are designed to help administrators and IT professionals with tasks such as discovering and mapping network devices, performing detailed scans of IP addresses and open ports, and querying network services like Active Directory.",
    ),
    "Exfiltration": (
        "exploitation",
        "T0008",
        "Exfiltration Tools",
        "File synchronization and management tools are designed to facilitate the efficient transfer, backup, and synchronization of files across various platforms and cloud storage services.",
    ),
    "LOLBAS": (
        "exploitation",
        "T0007",
        "Living-off-the-Land Binaries and Scripts",
        "Windows environments are equipped with a wide array of command-line utilities. These tools collectively provide robust support for efficient system management, troubleshooting, and optimization, helping administrators maintain secure, stable, and high-performing Windows environments.",
    ),
    "Networking": (
        "exploitation",
        "T0006",
        "Networking Tools",
        "There are a number of network tunneling tools available online for managing and interacting with systems across different environments. They allow users to securely connect to remote servers or services through encrypted channels that can bypass network restrictions and firewalls. These tools may also expose local development servers to the internet for testing and sharing. They are widely used for tasks like remote administration and development workflows, offering flexibility in network management.",
    ),
    "Offsec": (
        "exploitation",
        "T0005",
        "Offensive Security",
        "Offensive security tools are developed by professional ethical hackers to simulate cyber-attacks and evaluate an organization's defenses. These tools offer powerful features for post-exploitation activities, such as stealthy communications, lateral movement, and advanced command and control capabilities. Some tools focus on evasion techniques to bypass modern security defenses, allowing for realistic threat simulations and payload development.",
    ),
    "RMM-Tools": (
        "exploitation",
        "T0002",
        "Remote Monitoring & Management Tools",
        "An RMM (Remote Monitoring and Management) tool is a type of software used by IT professionals and managed service providers (MSPs) to remotely monitor, manage, and maintain IT systems, networks, and devices. These tools are designed to improve the efficiency of IT operations by enabling technicians to handle tasks from a centralized location without the need for physical access to client devices.",
    ),
}

COMBINED_GROUP_NAME = "all-groups-combined"


class Parser:
    _fs = None
    CREATED_BY_REF = "identity--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5"
    OBJECT_MARKING_REFS = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5",
    ]
    valid_groups = None

    def __init__(self, write_fs=False, group_name=None):
        self.__parsed_groups = {}
        self.__parsed_objects = []
        self.__added_objects = set()
        self.group_name = group_name
        self.session = requests.Session()
        self.session.headers = {"X-API-KEY": RANSOMWARE_LIVE_API_KEY}
        if write_fs:
            fs_path = Path("outputs/stix2_objects")
            if group_name:
                fs_path = fs_path / group_name
            shutil.rmtree(fs_path, ignore_errors=True)
            fs_path.mkdir(parents=True, exist_ok=True)
            self._fs = FileSystemStore(stix_dir=fs_path, allow_custom=True)
        self.locations = {
            location["country"]: location
            for location in retriever.get_location_objects()
        }
        self.add_object(retriever.get_default_objects())
        if not self.valid_groups:
            self.valid_groups = self.get_groups()

    def get_groups(self):
        r = self.session.get("https://api-pro.ransomware.live/groups")
        groups: dict[str, dict] = {
            group["group"]: group for group in r.json()["groups"]
        }
        r2 = self.session.get("https://api-pro.ransomware.live/iocs")
        for ioc in r2.json()["groups"]:
            group_name = ioc["group"].lower()
            with contextlib.suppress(KeyError):
                groups[group_name].update(iocs=ioc)
        return groups

    def add_object(self, object):
        if isinstance(object, list):
            for obj in object:
                self.add_object(obj)
            return
        if object["id"] in self.__added_objects:
            return
        self.__added_objects.add(object["id"])
        self.__parsed_objects.append(object)
        self._fs and self._fs.add(object)

    @property
    def parsed_objects(self):
        return self.__parsed_objects

    @property
    def bundle(self):
        return Bundle(
            type="bundle",
            id="bundle--" + str(uuid.uuid4()),
            objects=self.parsed_objects,
            allow_custom=True,
        )

    def parse_group(self, group):
        group_name = group["group"]
        slugs = []
        for location in group["locations"]:
            location["lastscrape"] = parse_date(location["lastscrape"])
            location["updated"] = parse_date(location["updated"])
            slugs.append(dict(source_name="darkweb_site", url=location["slug"]))
        group["locations"] = sorted(
            group["locations"], key=lambda x: x["updated"] or datetime.min, reverse=True
        )
        obj = IntrusionSet(
            id="intrusion-set--" + str(uuid.uuid5(NAMESPACE, group_name)),
            created=parse_date(group['firstseen']),  # we can';t have this changing because then s2a would always upload new items every time we upload
            modified=group["locations"] and group["locations"][0]["updated"],
            name=group_name,
            description=group.get("description"),
            primary_motivation="organizational-gain",
            # threat_actor_types=[ "crime-syndicate"],
            resource_level="team",
            object_marking_refs=self.OBJECT_MARKING_REFS,
            created_by_ref=self.CREATED_BY_REF,
            external_references=[
                {"source_name": "ransomware.live", "url": group["url"]}
            ]
            + slugs,
        )
        ttp_objects = self.parse_ttp(obj, group["ttps"])
        ioc_objects = self.parse_group_iocs(obj)
        self.__parsed_groups[group_name] = obj
        self.add_object(obj)
        self.add_object(ioc_objects)
        self.add_object(ttp_objects)
        self.parse_tools(obj, group["tools"])
        return obj
    
    def parse_group_iocs(self, group_object):
        group = self.valid_groups.get(group_object['name'])
        if not group:
            return []
        ioc_stat = group.get('iocs')
        if not ioc_stat:
            return []
        objects = []
        resp = self.session.get(f"https://api-pro.ransomware.live/iocs/{ioc_stat['group']}")
        resp.raise_for_status()
        iocs = resp.json()['iocs']
        if ioc_stat['ioc_types'].get('btc', 0) > 0:
            addresses = iocs['btc']
            wallet_objects = self.parse_addresses(group_object, addresses)
            objects.extend(wallet_objects)
        return objects

    def parse_tools(self, group_obj, tools):
        if not tools:
            return
        for attack_type, tool_names in tools.items():
            tool_type, tactic_obj = self.get_tool_attack_pattern(attack_type)
            for tool_name in tool_names:
                tool = Tool(
                    id="tool--" + str(uuid.uuid5(NAMESPACE, tool_name)),
                    created_by_ref=self.CREATED_BY_REF,
                    created="2020-01-01T00:00:00.000Z",
                    modified="2020-01-01T00:00:00.000Z",
                    name=tool_name,
                    tool_types=[tool_type],
                    kill_chain_phases=[
                        dict(
                            kill_chain_name="ransomware2stix",
                            phase_name=tactic_obj["x_mitre_shortname"],
                        )
                    ],
                    object_marking_refs=self.OBJECT_MARKING_REFS,
                    allow_custom=True,
                )
                self.add_object(tool)
                self.add_object(
                    Relationship(
                        id="relationship--"
                        + get_relationship_id(tool.id, tactic_obj["id"]),
                        source_ref=tool.id,
                        target_ref=tactic_obj["id"],
                        created=tool.created,
                        modified=tool.modified,
                        object_marking_refs=tool.object_marking_refs,
                        created_by_ref=tool.created_by_ref,
                        relationship_type="uses",
                        description=f"{tool.name} is used for {tactic_obj['name']}",
                        allow_custom=True,
                    )
                )

                self.add_object(
                    Relationship(
                        id="relationship--"
                        + get_relationship_id(group_obj.id, tool["id"]),
                        source_ref=group_obj.id,
                        target_ref=tool["id"],
                        created=tool.created,
                        modified=tool.modified,
                        object_marking_refs=group_obj.object_marking_refs,
                        created_by_ref=group_obj.created_by_ref,
                        relationship_type="uses",
                        description=f"{group_obj.name} uses {tool.name}",
                        allow_custom=True,
                    )
                )

    def get_tool_attack_pattern(self, tool_name):
        tool_type, tool_id, name, description = TOOL_MAPPING[tool_name]
        tool = dict(
            id="x-mitre-tactic--" + str(uuid.uuid5(NAMESPACE, name)),
            type="x-mitre-tactic",
            created_by_ref=self.CREATED_BY_REF,
            created="2020-01-01T00:00:00.000Z",
            modified="2020-01-01T00:00:00.000Z",
            name=name,
            description=description,
            external_references=[
                dict(
                    source_name="ransomware2stix",
                    external_id=tool_id,
                    url="https://github.com/muchdogesec/ransomware2stix",
                )
            ],
            x_mitre_shortname=tool_name,
            object_marking_refs=self.OBJECT_MARKING_REFS,
        )
        self.add_object(tool)
        return tool_type, tool

    def parse_addresses(self, group_object, btc_addresses):
        retval = []
        for addr in btc_addresses:
            obj = crypto2stix.Crypto2Stix().create_wallet_object(addr)
            rel = Relationship(
                id="relationship--" + get_relationship_id(group_object.id, obj["id"]),
                source_ref=group_object.id,
                target_ref=obj["id"],
                created=group_object.created,
                modified=group_object.modified,
                object_marking_refs=group_object.object_marking_refs,
                created_by_ref=group_object.created_by_ref,
                relationship_type="uses",
                description=f"{group_object.name} uses {addr}",
                allow_custom=True,
            )
            retval.append(obj)
            retval.append(rel)
        return retval

    def parse_ttp(self, group_object, ttps):
        techniques = {}
        for tactic in ttps:
            for technique in tactic["techniques"]:
                techniques[technique["technique_id"]] = technique

        attack_objects = retriever.get_attack_objects(list(techniques.keys()))
        relationship_objects = []
        for obj in attack_objects:
            attack_id = obj["external_references"][0]["external_id"]
            detail = techniques[attack_id]['technique_details']
            relationship_objects.append(
                Relationship(
                    id="relationship--"
                    + get_relationship_id(group_object.id, obj["id"]),
                    source_ref=group_object.id,
                    target_ref=obj["id"],
                    created=group_object.created,
                    modified=group_object.modified,
                    object_marking_refs=group_object.object_marking_refs,
                    created_by_ref=group_object.created_by_ref,
                    relationship_type="uses",
                    description=f"{group_object.name} uses {attack_id} [{detail}]",
                    allow_custom=True,
                )
            )
        return attack_objects + relationship_objects

    def parse_victim(self, victim):
        victim.update(
            group=victim.get("group", victim.get("group_name")),
            attackdate=victim.get("attackdate", victim.get("published")),
            claim_url=victim.get("claim_url", victim.get("post_url")),
            domain=victim.get("domain", victim.get("website")),
            victim=victim.get("victim", victim.get("post_title")),
        )
        group_name = victim["group"]
        victim_name = victim["victim"].lower()

        mapped_sector = SECTOR_MAPPING.get(victim["activity"])
        if victim["activity"] not in SECTOR_MAPPING:
            logging.warning(
                "unrecognized activity/sector for victim (%s): %s",
                victim_name,
                victim["activity"],
            )
            SECTOR_MAPPING.update({victim["activity"]: None})
        identity = Identity(
            id="identity--" + str(uuid.uuid5(NAMESPACE, victim_name)),
            created_by_ref=self.CREATED_BY_REF,
            created="2020-01-01T00:00:00.000Z",
            modified="2020-01-01T00:00:00.000Z",
            name=victim_name,
            description=victim["description"],
            contact_information=victim["domain"].lower(),
            identity_class="organization",
            sectors=mapped_sector,
            object_marking_refs=self.OBJECT_MARKING_REFS,
        )
        self.add_object(identity)

        location = self.locations.get(victim["country"])
        if location:
            self.add_object(location)
            self.add_object(
                Relationship(
                    id="relationship--"
                    + get_relationship_id(identity.id, location["id"]),
                    source_ref=identity.id,
                    target_ref=location["id"],
                    created=identity.created,
                    modified=identity.modified,
                    object_marking_refs=identity.object_marking_refs,
                    created_by_ref=identity.created_by_ref,
                    relationship_type="located-in",
                    description=f"{identity.name} is located in {victim['country']}",
                    allow_custom=True,
                )
            )

        incident_name = f"{victim_name} ransomed by {group_name}"
        attack_date = format_datetime(parse_date(victim["attackdate"]))
        incident_id = str(uuid.uuid5(NAMESPACE, f"{incident_name}+{attack_date}"))
        incident = Incident(
            id="incident--" + incident_id,
            object_marking_refs=self.OBJECT_MARKING_REFS,
            created_by_ref=self.CREATED_BY_REF,
            created=attack_date,
            modified=parse_date(victim["discovered"]),
            name=incident_name,
            description=victim["claim_url"],
        )
        self.add_object(incident)
        try:
            group = self.get_group(group_name)
            self.add_object(
                Relationship(
                    id="relationship--"
                    + get_relationship_id(group["id"], identity.id, attack_date),
                    target_ref=identity.id,
                    source_ref=group["id"],
                    created=attack_date,
                    modified=incident.modified,
                    object_marking_refs=identity.object_marking_refs,
                    created_by_ref=identity.created_by_ref,
                    relationship_type="victim-of",
                    description=f"{identity.name} was a victim of {group['name']}",
                    allow_custom=True,
                )
            )
            self.add_object(
                Relationship(
                    id="relationship--"
                    + get_relationship_id(group["id"], incident.id, attack_date),
                    target_ref=incident.id,
                    source_ref=group["id"],
                    created=attack_date,
                    modified=incident.modified,
                    object_marking_refs=identity.object_marking_refs,
                    created_by_ref=identity.created_by_ref,
                    relationship_type="attributed-to",
                    description=f"{group['name']} launch targetted {identity.name}",
                    allow_custom=True,
                )
            )
        except Exception as e:
            logging.debug(f"failed to get group {group_name}: {e}", exc_info=True)
        return identity

    def get_group(self, group_name):
        if group_name not in self.valid_groups:
            raise GroupError(f"skip fetching group")
        if group_name in self.__parsed_groups:
            return self.__parsed_groups[group_name]
        url = f"https://api-pro.ransomware.live/groups/{group_name}"
        resp = self.session.get(url)
        resp_data = resp.json()
        return self.parse_group(resp_data)

    @classmethod
    def parse_all_victims(
        cls,
        start_date=None,
        end_date=None,
        combine_bundle=False,
        groups=[],
        write_fs=False,
    ):
        parsers: dict[str, Parser] = {}
        if combine_bundle:
            default_parser = Parser(write_fs=write_fs)
        if not start_date:
            start_date = datetime.min
        if not end_date:
            end_date = datetime.max
        for i, victim in enumerate(retriever.get_victims()):
            discovered_on = parse_date(victim["discovered"])
            if discovered_on < start_date or discovered_on > end_date:
                continue

            group_name = victim.get("group", victim.get("group_name"))
            if groups and group_name not in groups:
                continue
            if not combine_bundle:
                parser = parsers.get(group_name)
                if not parser:
                    parser = parsers.setdefault(
                        group_name, Parser(write_fs=write_fs, group_name=group_name)
                    )
            else:
                parser = parsers.setdefault(COMBINED_GROUP_NAME, default_parser)

            try:
                parser.parse_victim(victim)
            except Exception as e:
                logging.exception(f"failed on [{i}] - {victim}")
        return parsers
