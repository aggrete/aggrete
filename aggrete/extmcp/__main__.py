import sys
from . import cli

raise SystemExit(cli(["extmcp", *sys.argv[1:]]))
