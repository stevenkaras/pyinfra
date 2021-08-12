from pyinfra.api import operation
from pyinfra.facts.ipset import IpsetSet, IpsetEntries


@operation
def ipset_set(
    set_name,
    set_type="hash:net",
    extras="",
    present=True,
    state=None,
    host=None,
):
    """
    Create/delete a set

    + set_name: name of the set
    + set_type: the type of the set
    + extras: extra flags
    + present: whether the set should be present or not

    Examples:

    .. code:: python
        # Create an internal allowlist if it doesn't yet exist
        ipset.ipset_set(
            name='Ensure internal allowlist exists',
            set_name='internal-allowlist',
            set_type='hash:net',
            extras='comment',
        )
    """
    sets = host.get_fact(IpsetSet)
    if set_name in sets:
        if present:
            # TODO: raise if the existing set doesn't match the one described here
            host.noop(f"ipset {set_name} exists")
            return
        else:
            yield f"ipset destroy {set_name}"
            sets.pop(set_name)
    else:
        if present:
            yield f"ipset create {set_name} {set_type} {extras}"
            sets[set_name] = {
                "name": set_name,
                "type": set_type,
                "header": extras,
                "references": 0,
                "num_entries": 0,
            }
        else:
            host.noop(f"ipset {set_name} does not exist")
            return


@operation
def ipset_entry(
    set_name,
    entry,
    extras="",
    present=True,
    state=None,
    host=None,
):
    """
    Add/remove an entry from a set

    + set_name: name of the set
    + entry: the main entry content (i.e. CIDR; CIDR,interface; IP, etc)
    + extras: extra flags
    + present: whether the entry should be present or not

    Examples:

    .. code:: python
        # Add docker network to allowlist
        ipset.ipset_entry(
            name='Allow docker network traffic',
            set_name='internal-allowlist',
            entry='172.16.0.0/12',
            extras='comment "docker networking"',
        )
    """
    set_entries = host.get_fact(IpsetEntries, set_name=set_name)
    set_entry = {"setname": set_name, "entry": entry, "extras": extras}
    if entry in set_entries:
        if present:
            # avoid issuing updates if the entries are identical
            if not IpsetEntries.equivalent_entries(set_entry, set_entries[entry]):
                yield f"ipset add {set_name} {entry} {extras} -exist"
                set_entries[entry] = set_entry
            else:
                host.noop(f"ipset entry {entry} already in {set_name}")
                return
        else:
            yield f"ipset del {set_name} {entry}"
            set_entries.pop(entry)
    else:
        if present:
            yield f"ipset add {set_name} {entry} {extras}"
            set_entries[entry] = set_entry
        else:
            host.noop(f"ipset entry {entry} already not in {set_name}")
            return
