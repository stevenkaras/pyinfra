'''
The iptables modules handles iptables rules
'''

from __future__ import unicode_literals

import six

from pyinfra.api import operation
from pyinfra.api.exceptions import OperationError
from pyinfra.facts.iptables import (
    Ip6tablesChains,
    Ip6tablesRules,
    IptablesChains,
    IptablesRules,
    parse_iptables_rule,
)


@operation
def chain(
    chain, present=True,
    table='filter', policy=None, version=4,
    state=None, host=None,
):
    '''
    Add/remove/update iptables chains.

    + chain: the name of the chain
    + present: whether the chain should exist
    + table: the iptables table this chain should belong to
    + policy: the policy this table should have
    + version: whether to target iptables or ip6tables

    Policy:
        These can only be applied to system chains (FORWARD, INPUT, OUTPUT, etc).
    '''

    chains = (
        host.get_fact(IptablesChains, table=table)
        if version == 4
        else host.get_fact(Ip6tablesChains, table=table)
    )

    command = 'iptables' if version == 4 else 'ip6tables'
    command = '{0} -t {1}'.format(command, table)

    if not present:
        if chain in chains:
            yield '{0} -X {1}'.format(command, chain)
        else:
            host.noop('iptables chain {0} does not exist'.format(chain))
        return

    if present:
        if chain not in chains:
            yield '{0} -N {1}'.format(command, chain)
        else:
            host.noop('iptables chain {0} exists'.format(chain))

        if policy:
            if chain not in chains or chains[chain] != policy:
                yield '{0} -P {1} {2}'.format(command, chain, policy)


@operation
def rule(
    chain, jump, present=True,
    table='filter', append=True, version=4,
    # Core iptables filter arguments
    protocol=None, not_protocol=None,
    source=None, not_source=None,
    destination=None, not_destination=None,
    in_interface=None, not_in_interface=None,
    out_interface=None, not_out_interface=None,
    # After-rule arguments
    to_destination=None, to_source=None, to_ports=None, log_prefix=None, reject_with=None,
    # Extras and extra shortcuts
    destination_port=None, source_port=None, extras='',
    state=None, host=None,
):
    '''
    Add/remove iptables rules.

    + chain: the chain this rule should live in
    + jump: the target of the rule
    + table: the iptables table this rule should belong to
    + append: whether to append or insert the rule (if not present)
    + version: whether to target iptables or ip6tables

    Iptables args:

    + protocol/not_protocol: filter by protocol (tcp or udp)
    + source/not_source: filter by source IPs
    + destination/not_destination: filter by destination IPs
    + in_interface/not_in_interface: filter by incoming interface
    + out_interface/not_out_interface: filter by outgoing interface
    + to_destination: where to route to when jump=DNAT
    + to_source: where to route to when jump=SNAT
    + to_ports: where to route to when jump=REDIRECT
    + log_prefix: prefix for the log of this rule when jump=LOG

    Extras:

    + extras: a place to define iptables extension arguments (eg --limit, --physdev)
    + destination_port: destination port (requires protocol)
    + source_port: source port (requires protocol)

    Examples:

    .. code:: python

        iptables.rule(
            name='Block SSH traffic',
            chain='INPUT',
            jump='DROP',
            destination_port=22
        )

        iptables.rule(
            name='NAT traffic on from 8.8.8.8:53 to 8.8.4.4:8080',
            chain='PREROUTING',
            jump='DNAT',
            table='nat',
            source='8.8.8.8', destination_port=53,
            to_destination='8.8.4.4:8080'
        )
    '''

    if isinstance(to_ports, int):
        to_ports = '{0}'.format(to_ports)

    # These are only shortcuts for extras
    if destination_port:
        extras = '{0} --dport {1}'.format(extras, destination_port)

    if source_port:
        extras = '{0} --sport {1}'.format(extras, source_port)

    # When protocol is set, the extension is automagically added by iptables (which shows
    # in iptables-save): http://ipset.netfilter.org/iptables-extensions.man.html
    if protocol and '-m {0}'.format(protocol) not in extras:
        extras = '{0} -m {1}'.format(extras, protocol)

    # --dport and --sport do not work without a protocol (because they need -m [tcp|udp]
    if not protocol and (destination_port or source_port):
        raise OperationError(
            'iptables cannot filter by destination_port/source_port without a protocol',
        )

    # Verify NAT arguments, --to-destination only w/table=nat, jump=DNAT
    if to_destination and (table != 'nat' or jump != 'DNAT'):
        raise OperationError(
            'iptables only supports to_destination on the nat table and the DNAT jump '
            '(table={0}, jump={1})'.format(table, jump),
        )

    # As above, --to-source only w/table=nat, jump=SNAT
    if to_source and (table != 'nat' or jump != 'SNAT'):
        raise OperationError(
            'iptables only supports to_source on the nat table and the SNAT jump '
            '(table={0}, jump={1})'.format(table, jump),
        )

    # As above, --to-ports only w/table=nat, jump=REDIRECT
    if to_ports and (table != 'nat' or jump != 'REDIRECT'):
        raise OperationError(
            'iptables only supports to_ports on the nat table and the REDIRECT jump '
            '(table={0}, jump={1})'.format(table, jump),
        )

    # --log-prefix is only supported with jump=LOG
    if log_prefix and jump != 'LOG':
        raise OperationError(
            'iptables only supports log_prefix with the LOG jump '
            '(jump={0})'.format(jump),
        )

    # --reject-with is only supported with jump=REJECT
    if reject_with and jump != 'REJECT':
        raise OperationError(
            'iptables only supports reject_with with the REJECT jump '
            '(jump={0})'.format(jump),
        )

    def _normalize_cidr(cidr, version):
        if version == 4 and cidr and '/' not in cidr:
            return '{0}/32'.format(cidr)
        elif version == 6 and cidr and '/' not in cidr:
            return '{0}/128'.format(cidr)
        else:
            return cidr

    source = _normalize_cidr(source, version)
    not_source = _normalize_cidr(not_source, version)
    destination = _normalize_cidr(destination, version)
    not_destination = _normalize_cidr(not_destination, version)

    rules = (
        host.get_fact(IptablesRules, table=table)
        if version == 4
        else host.get_fact(Ip6tablesRules, table=table)
    )

    command = [
        'iptables' if version == 4 else 'ip6tables',
        # Add the table
        '-t', table,
    ]

    # build the action to parse and check if it already exists
    if present:
        action = '-A' if append else '-I'
    else:
        action = '-D'

    args = [
        # Add the action and target chain
        action, chain,
    ]

    def add_args(arg_flags, arg):
        if not arg:
            return

        if isinstance(arg_flags, (tuple, list)):
            args.extend(arg_flags)
        else:
            args.append(arg_flags)

        args.append(arg)

    add_args('-p', protocol)
    add_args('-s', source)
    add_args('-i', in_interface)
    add_args('-o', out_interface)
    add_args(('!', '-p'), not_protocol)
    add_args(('!', '-s'), not_source)
    add_args(('!', '-i'), not_in_interface)
    add_args(('!', '-o'), not_out_interface)
    add_args((), extras.strip())
    add_args('-j', jump)
    add_args('--log-prefix', log_prefix)
    add_args('--to-destination', to_destination)
    add_args('--to-source', to_source)
    add_args('--to-ports', to_ports)
    add_args('--reject-with', reject_with)

    definition = parse_iptables_rule(' '.join(args))
    command = ' '.join(command + args)

    print(f"DEBUG: {definition=}\n\n{rules=}")

    if definition in rules:
        if present:
            host.noop('iptables {0} rule exists'.format(chain))
            return
        else:
            yield command
            rules.remove(definition)
    else:
        if present:
            yield command
            rules.append(definition)
        else:
            host.noop('iptables {0} rule does not exists'.format(chain))
            return
