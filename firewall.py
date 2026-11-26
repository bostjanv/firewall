import argparse
import json
import subprocess
import sys

EXAMPLES = """\
Rule examples (use with: firewall.py add RULE):
  ip saddr 192.168.64.0/24 tcp dport 8000 accept
  ip saddr { 198.51.100.7, 203.0.113.9 } drop
  ip saddr 203.0.113.0/24 tcp dport 22 reject
  ip6 saddr 2001:db8::/32 drop
  tcp dport 22 accept
  tcp dport { 80, 443 } accept
  tcp dport 3000-3010 accept
  udp dport 53 accept
  iifname eth1 tcp dport 22 drop
  icmp type echo-request drop
  tcp dport 22 ct state new limit rate 10/minute accept

With comment (or use: firewall.py add --comment NAME RULE):
  ip saddr 203.0.113.5 drop comment "block-scanner"
  ip saddr 192.168.1.0/24 tcp dport 8000 accept comment "lan-web"
  tcp dport 22 accept comment "ssh"

With packet counter (list shows packets/bytes matched):
  ip saddr 203.0.113.5 counter drop
  tcp dport 22 counter accept
  ip saddr 10.0.0.0/8 counter drop comment "block-10"
  tcp dport { 80, 443 } counter accept comment "web"

Quote the whole rule when it has "..." or { }, e.g.:
  firewall.py add 'tcp dport 22 counter accept comment "ssh"'
"""


class DynamicFirewall:
    def __init__(self):
        self.chain = ["inet", "filter", "dynamic_input"]

    def _nft(self, *args):
        return subprocess.check_output(
            ["sudo", "nft", *args],
            text=True,
        )

    def add_rule(self, *args):
        self._nft("add", "rule", *self.chain, *args)

    def delete_rule(self, handle):
        self._nft(
            "delete",
            "rule",
            *self.chain,
            "handle",
            str(handle),
        )

    def list_rules(self):
        output = self._nft(
            "-j",
            "-a",
            "list",
            "chain",
            *self.chain,
        )
        return [
            entry["rule"] for entry in json.loads(output)["nftables"] if "rule" in entry
        ]

    def list_rules_text(self):
        return self._nft("-a", "list", "chain", *self.chain)

    def get_handle(self, comment):
        return next(
            (
                rule["handle"]
                for rule in self.list_rules()
                if rule.get("comment") == comment
            ),
            None,
        )

    def flush(self):
        self._nft("flush", "chain", *self.chain)


def cmd_list(fw, args):
    if args.json:
        print(json.dumps(fw.list_rules(), indent=2))
    else:
        print(fw.list_rules_text(), end="")
    return 0


def cmd_flush(fw, args):
    if not args.yes:
        chain = " ".join(fw.chain)
        try:
            answer = input(f"Delete ALL rules in chain '{chain}'? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1
    fw.flush()
    print("Rules flushed.")
    return 0


def cmd_add(fw, args):
    rule = list(args.rule)
    if args.comment is not None:
        if '"' in args.comment:
            print("error: comment must not contain double quotes", file=sys.stderr)
            return 1
        rule += ["comment", f'"{args.comment}"']
    fw.add_rule(*rule)
    print("Rule added.")
    return 0


def cmd_remove(fw, args):
    fw.delete_rule(args.handle)
    print(f"Removed rule with handle {args.handle}.")
    return 0


def cmd_examples(fw, args):
    print(EXAMPLES, end="")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Manage rules in the nftables 'inet filter dynamic_input' chain.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_list = sub.add_parser("list", help="list rules in the chain")
    p_list.add_argument(
        "--json", action="store_true", help="output rules as JSON objects"
    )
    p_list.set_defaults(func=cmd_list)

    p_flush = sub.add_parser("flush", help="delete all rules in the chain")
    p_flush.add_argument(
        "-y", "--yes", action="store_true", help="do not ask for confirmation"
    )
    p_flush.set_defaults(func=cmd_flush)

    p_add = sub.add_parser(
        "add",
        help="add a rule to the chain",
        description="Add a rule. RULE is nft rule syntax, e.g. "
        "'ip saddr 10.0.0.1 tcp dport 22 accept'. "
        "Use '--' before the rule if it contains tokens starting with '-'.",
    )
    p_add.add_argument("-c", "--comment", help="comment to tag the rule")
    p_add.add_argument("rule", nargs="+", metavar="RULE", help="nft rule tokens")
    p_add.set_defaults(func=cmd_add)

    p_remove = sub.add_parser("remove", help="remove a rule by its handle")
    p_remove.add_argument(
        "handle", type=int, help="handle of the rule to remove (shown by 'list')"
    )
    p_remove.set_defaults(func=cmd_remove)

    p_examples = sub.add_parser("examples", help="show usage examples")
    p_examples.set_defaults(func=cmd_examples)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    fw = DynamicFirewall()
    try:
        return args.func(fw, args)
    except FileNotFoundError as e:
        print(f"error: command not found: {e.filename}", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"error: nft failed with exit code {e.returncode}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
