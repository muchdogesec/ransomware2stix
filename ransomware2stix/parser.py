import logging
import os
import re
import uuid
from dateutil.parser import parse as dateutitl_parse_date

import requests
import stix2

from ransomware2stix import retriever
from stix2 import (
    IntrusionSet,
    Relationship,
    Identity,
    Incident,
    Tool,
    Bundle,
    Note,
)
from stix2.utils import format_datetime, STIXdatetime, Precision
from datetime import UTC, datetime
from stix2extensions.tools import crypto2stix

NAMESPACE = uuid.UUID("7bae962c-40ae-5817-8cdc-e1b6eb4f38f5")
DEFAULT_DATE = datetime(2020, 1, 1)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

RANSOMWARE_LIVE_API_KEY = os.environ["RANSOMWARE_LIVE_API_KEY"]


def parse_date(date_string: str):
    if not date_string:
        return
    dt = STIXdatetime(
        dateutitl_parse_date(date_string),
        precision=Precision.MILLISECOND,
    )
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=UTC)
    return dt


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

    def __init__(self, start_date=None, end_date=None, process_all_ransomnotes=True):
        self.__parsed_objects = []
        self.__added_objects = set()
        self.start_date = start_date
        self.end_date = end_date
        self.process_all_ransomnotes = process_all_ransomnotes
        self.session = requests.Session()
        self.session.headers = {"X-API-KEY": RANSOMWARE_LIVE_API_KEY}

        self.locations = {
            location["country"]: location
            for location in retriever.get_location_objects()
        }
        self.ioc_stats = self.get_ioc_stats()
        self.ransomnote_stats = self.get_ransomnote_stats()

    def get_ioc_stats(self):
        r = self.session.get("https://api-pro.ransomware.live/iocs")
        return {ioc_stat["group"].lower(): ioc_stat for ioc_stat in r.json()["groups"]}

    def get_ransomnote_stats(self):
        r = self.session.get("https://api-pro.ransomware.live/ransomnotes")
        return {
            stat["group"].lower(): stat["ransomnotes_count"]
            for stat in r.json()["groups"]
        }

    def get_groups(self):
        r = self.session.get("https://api-pro.ransomware.live/groups")
        groups: dict[str, dict] = {
            group["group"]: group for group in r.json()["groups"]
        }
        return groups

    def add_objects(self, object):
        if isinstance(object, list):
            for obj in object:
                self.add_objects(obj)
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

    def reset(self):
        self.__parsed_objects = []
        self.__added_objects = set()
        self.victims = set()

    def build_group_bundle(self, group):
        self.add_objects(retriever.get_default_objects())
        group_data = self.get_group(group["group"])
        if group["altname"]:
            group_data["aliases"] = [group["altname"]]
        self.parse_group(group_data)
        return self.__parsed_objects

    def parse_group(self, group):
        group_name = group["group"]
        slugs = []
        for location in group["locations"]:
            slugs.append(dict(source_name="darkweb_site", url=location["slug"]))
        obj = IntrusionSet(
            id="intrusion-set--" + str(uuid.uuid5(NAMESPACE, group_name)),
            created=parse_date(group["firstseen"]),
            modified=parse_date(group["lastseen"]),
            name=group_name,
            description=group.get("description"),
            primary_motivation="organizational-gain",
            aliases=group.get("aliases", []),
            resource_level="team",
            object_marking_refs=self.OBJECT_MARKING_REFS,
            created_by_ref=self.CREATED_BY_REF,
            external_references=[
                {"source_name": "ransomware.live", "url": group["url"]}
            ]
            + slugs,
        )
        ttp_objects = self.parse_ttp(obj, group["ttps"])
        vulnerability_objects = self.parse_vulnerabilities(
            obj, group["vulnerabilities"]
        )
        ioc_objects = self.parse_group_iocs(obj, group)
        self.add_objects(obj)
        self.add_objects(ioc_objects)
        self.add_objects(ttp_objects)
        self.add_objects(vulnerability_objects)
        self.parse_tools(obj, group["tools"])
        if group["victims"]:
            self.fetch_and_parse_victims(obj, group)
        if self.victims or self.process_all_ransomnotes:
            # only fetch ransomnote_objects if there are new victims
            ransomnote_objects = self.parse_group_ransomnotes(obj)
            self.add_objects(ransomnote_objects)

        return obj

    def parse_vulnerabilities(self, group_obj, vulnerabilities):
        cve_ids = set()
        for cve in vulnerabilities:
            cve_id = cve["CVE"]
            cve_ids.update(CVE_RE.findall(cve_id))
        if not cve_ids:
            return []
        orig_len = len(cve_ids)
        objects = []
        for cve in retriever.get_vulnerability_objects(cve_ids):
            cve_ids.difference_update([cve["name"]])
            objects.append(cve)
            objects.append(
                Relationship(
                    id="relationship--"
                    + get_relationship_id(group_obj["id"], cve["id"]),
                    source_ref=group_obj["id"],
                    target_ref=cve["id"],
                    created=group_obj["created"],
                    modified=group_obj["modified"],
                    object_marking_refs=group_obj["object_marking_refs"],
                    created_by_ref=group_obj["created_by_ref"],
                    relationship_type="exploits",
                    description=f"{group_obj['name']} exploits {cve['name']}",
                    allow_custom=True,
                )
            )
        if cve_ids:
            logging.warning(
                f"Found {orig_len - len(cve_ids)} out of {orig_len} CVEs. Missing: {cve_ids}"
            )
        return objects

    def parse_group_ransomnotes(self, group_obj):
        group_name = group_obj["name"]
        if not self.ransomnote_stats.get(group_name.lower()):
            return []
        objects = []
        resp = self.session.get(
            f"https://api-pro.ransomware.live/ransomnotes/{group_name}"
        )
        resp.raise_for_status()
        note_names = resp.json()["ransomnotes"]
        for note_name in note_names:
            try:
                objects.extend(self.process_ransomnote(group_obj, note_name))
            except Exception as e:
                logging.warning(f"Could not parse ransomnote `{note_name}` for `{group_name}`: {e}")
        return objects

    def process_ransomnote(self, group_obj, note_name):
        group_name = group_obj["name"]
        resp = self.session.get(
            f"https://api-pro.ransomware.live/ransomnotes/{group_name}/{note_name}"
        )
        resp.raise_for_status()
        response_data = resp.json()
        response_data["group_name"] = group_name.lower()
        note_id = str(uuid.uuid5(NAMESPACE, f"{group_name}+{note_name}"))
        note_obj = Note(
            id="note--" + note_id,
            created_by_ref=group_obj.created_by_ref,
            created=group_obj.created,
            modified=group_obj.modified,
            object_marking_refs=group_obj.object_marking_refs,
            abstract=note_name,
            content=response_data["content"],
            object_refs=[group_obj["id"]],
            external_references=[
                {
                    "source_name": "ransomware.live",
                    "url": "https://www.ransomware.live/ransomnote/{group_name}/{note_name}{extension}".format_map(response_data),
                    "external_id": response_data["id"],
                }
            ],
        )
        rel = Relationship(
            id="relationship--" + get_relationship_id(group_obj["id"], note_obj["id"]),
            source_ref=note_obj["id"],
            target_ref=group_obj["id"],
            created=group_obj["created"],
            modified=group_obj["modified"],
            object_marking_refs=group_obj["object_marking_refs"],
            created_by_ref=group_obj["created_by_ref"],
            relationship_type="related-to",
            description=f"Note is used by {group_obj['name']}",
        )

        return (note_obj, rel)

    def parse_group_iocs(self, group_object, group_data):
        group_name = group_data["group"]
        if not self.ioc_stats.get(group_name.lower()):
            return []
        objects = []
        resp = self.session.get(
            f"https://api-pro.ransomware.live/iocs/{group_data['group']}"
        )
        resp.raise_for_status()
        iocs = resp.json()["iocs"]
        for ioc_type, ioc_values in iocs.items():
            match ioc_type:
                case "btc":
                    wallet_objects = self.parse_addresses(group_object, ioc_values)
                    objects.extend(wallet_objects)
                case "sha256" | "sha-256":
                    objects.extend(
                        self.parse_hashes(group_object, "SHA-256", ioc_values)
                    )
                case "sha1" | "sha-1":
                    objects.extend(self.parse_hashes(group_object, "SHA-1", ioc_values))
                case "md5":
                    objects.extend(self.parse_hashes(group_object, "MD5", ioc_values))
                case "url" | "ftp":
                    for url in ioc_values:
                        url_object = stix2.URL(
                            value=url,
                        )
                        objects.append(url_object)
                        objects.append(
                            Relationship(
                                id="relationship--"
                                + get_relationship_id(
                                    group_object.id, url_object["id"]
                                ),
                                source_ref=group_object.id,
                                target_ref=url_object["id"],
                                created=group_object.created,
                                modified=group_object.modified,
                                object_marking_refs=group_object.object_marking_refs,
                                created_by_ref=group_object.created_by_ref,
                                relationship_type="uses",
                                description=f"{group_object.name} uses {url}",
                                allow_custom=True,
                                external_references=[
                                    dict(
                                        source_name="url_type",
                                        external_id=ioc_type,
                                    )
                                ],
                            )
                        )
                case "email":
                    for email in ioc_values:
                        email_object = stix2.EmailAddress(
                            value=email,
                        )
                        objects.append(email_object)
                        objects.append(
                            Relationship(
                                id="relationship--"
                                + get_relationship_id(
                                    group_object.id, email_object["id"]
                                ),
                                source_ref=group_object.id,
                                target_ref=email_object["id"],
                                created=group_object.created,
                                modified=group_object.modified,
                                object_marking_refs=group_object.object_marking_refs,
                                created_by_ref=group_object.created_by_ref,
                                relationship_type="uses",
                                description=f"{group_object.name} uses {email}",
                                allow_custom=True,
                            )
                        )
                case "_":
                    logging.warning(
                        f"unrecognized ioc type for group {group_name}: {ioc_type}"
                    )
        return objects

    def parse_hashes(self, group_object, hash_type, hashes):
        objects = []
        for hash in hashes:
            try:
                file_object = stix2.File(
                    hashes={hash_type: hash},
                )
                objects.append(file_object)
                objects.append(
                    Relationship(
                        id="relationship--"
                        + get_relationship_id(group_object.id, file_object["id"]),
                        source_ref=group_object.id,
                        target_ref=file_object["id"],
                        created=group_object.created,
                        modified=group_object.modified,
                        object_marking_refs=group_object.object_marking_refs,
                        created_by_ref=group_object.created_by_ref,
                        relationship_type="uses",
                        description=f"{group_object.name} uses file with {hash_type}: {hash}",
                        allow_custom=True,
                    )
                )
            except Exception as e:
                logging.warning(
                    f"failed to parse {hash_type} hash ({hash}) for group {group_object['name']}: {e}"
                )
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
                self.add_objects(tool)
                self.add_objects(
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
                self.add_objects(
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
        self.add_objects(tool)
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
            detail = techniques[attack_id].get("technique_details", "")
            if detail:
                detail = " [" + detail + "]"
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
                    description=f"{group_object.name} uses {attack_id}{detail}",
                    allow_custom=True,
                )
            )
        return attack_objects + relationship_objects

    def parse_victim(self, group_obj, victim):
        group_name = victim["group"]
        victim_name = victim["victim"].lower()

        discovered_time = parse_date(victim['discovered'])
        attack_date = parse_date(victim['attackdate']) or discovered_time
        if (self.start_date and max(attack_date, discovered_time) < self.start_date) or (
            self.end_date and max(attack_date, discovered_time) > self.end_date
        ):
            return

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
            contact_information=victim["website"],
            identity_class="organization",
            sectors=mapped_sector,
            object_marking_refs=self.OBJECT_MARKING_REFS,
        )
        self.add_objects(identity)
        self.victims.add(identity.name)

        location = self.locations.get(victim["country"])
        if location:
            self.add_objects(location)
            self.add_objects(
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
        claim_url = victim["post_url"]
        incident_id = str(uuid.uuid5(NAMESPACE, f"{incident_name}+{victim['id']}"))
        incident = Incident(
            id="incident--" + incident_id,
            object_marking_refs=self.OBJECT_MARKING_REFS,
            created_by_ref=self.CREATED_BY_REF,
            created=attack_date,
            modified=discovered_time,
            name=incident_name,
            description=claim_url,
            external_references=[
                {"source_name": "ransomware.live", "url": victim["permalink"]},
            ],
        )
        self.add_objects(incident)
        self.add_objects(
            Relationship(
                id="relationship--"
                + get_relationship_id(group_obj["id"], identity.id, attack_date),
                target_ref=identity.id,
                source_ref=group_obj["id"],
                created=attack_date,
                modified=incident.modified,
                object_marking_refs=identity.object_marking_refs,
                created_by_ref=identity.created_by_ref,
                relationship_type="victim-of",
                description=f"{identity.name} was a victim of {group_obj['name']}",
                allow_custom=True,
            )
        )
        self.add_objects(
            Relationship(
                id="relationship--"
                + get_relationship_id(group_obj["id"], incident.id, attack_date),
                target_ref=incident.id,
                source_ref=group_obj["id"],
                created=attack_date,
                modified=incident.modified,
                object_marking_refs=identity.object_marking_refs,
                created_by_ref=identity.created_by_ref,
                relationship_type="attributed-to",
                description=f"{group_obj['name']} launch targetted {identity.name}",
                allow_custom=True,
            )
        )
        return identity

    def get_group(self, group_name):
        url = f"https://api-pro.ransomware.live/groups/{group_name}"
        resp = self.session.get(url)
        resp_data = resp.json()
        return resp_data

    def fetch_and_parse_victims(self, group_obj, group_data):
        group_name = group_data["group"]
        resp = self.session.get(
            f"https://api-pro.ransomware.live/victims/?group={group_name}"
        )
        resp.raise_for_status()
        for victim in resp.json()["victims"]:
            self.parse_victim(group_obj, victim)
