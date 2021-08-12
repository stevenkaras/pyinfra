"""
Manage ipset IP sets
"""
import re

from pyinfra.api import FactBase


class IpsetSet(FactBase):
    """
    Returns a dict of ip sets names to a dict containing some metadata:

    .. code:: python
        {
            'first_set': {
                'name': 'first_set',
                'type': 'hash:net',
                'revision': 6,
                'header': 'family inet hashsize 1024 maxelem 65536 comment',
                'memory_size': 958,
                'references': 1,
                'num_entries': 4,
            }
        }
    """

    def command(self, set_name=None):
        if set_name:
            return f"ipset list {set_name} -terse || if [ $? = 1 ]; then :; fi"
        else:
            return "ipset list -terse"

    requires_command = "ipset"

    default = dict

    IPSET_LIST_PATTERN = re.compile(
        r"""
            (?:^Name:\s+(?P<name>.*)$\n)
            (?:^Type:\s+(?P<type>.*)$\n)
            (?:^Revision:\s+(?P<revision>.*)$\n)
            (?:^Header:\s+(?P<header>.*)$\n)
            (?:^Size\ in\ memory:\s+(?P<memory_size>.*)$\n)
            (?:^References:\s+(?P<references>.*)$\n)
            (?:^Number\ of\ entries:\s+(?P<num_entries>.*)$\n?)
        """,
        re.MULTILINE | re.VERBOSE,
    )

    def process(self, output):
        sets = {}
        for match in self.IPSET_LIST_PATTERN.finditer("\n".join(output)):
            current_set = match.groupdict()
            current_set["revision"] = int(current_set["revision"])
            current_set["memory_size"] = int(current_set["memory_size"])
            current_set["references"] = int(current_set["references"])
            current_set["num_entries"] = int(current_set["num_entries"])
            sets[current_set["name"]] = current_set

        return sets


class IpsetEntries(FactBase):
    """
    Returns a dict of entries in a set:

    .. code:: python
        {
            '172.16.0.0/12': '172.16.0.0/12 comment "docker networking"',
            '10.19.0.0/16': '10.19.0.0/16 comment "corporate intranet"'
        }
    """

    def command(self, set_name):
        return (
            f"ipset list {set_name} -output save 2>/dev/null; if [ $? = 1 ]; then :; fi"
        )

    requires_command = "ipset"

    default = dict

    IPSET_ENTRY_PATTERN = re.compile(
        r"^add (?P<setname>\S+) (?P<entry>\S+) ?(?P<extras>.*)$"
    )

    def process(self, output):
        entries = {}
        for line in output:
            match = self.IPSET_ENTRY_PATTERN.match(line)
            if not match:
                continue

            entries[match.group("entry")] = match.groupdict()

        return entries

    @staticmethod
    def equivalent_entries(lhs: dict, rhs: dict):
        for attr in ("setname", "entry", "extras"):
            lhs_val = lhs.get(attr)
            if lhs_val is None:
                lhs_val = ""
            rhs_val = rhs.get(attr)
            if rhs_val is None:
                rhs_val = ""
            if lhs_val != rhs_val:
                return False
        return True
