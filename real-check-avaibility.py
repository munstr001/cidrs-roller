"""Compatibility entry point; run with --help for scanner options."""
from cidr_scanner import main, representative_ip as _representative_ip


if __name__ == '__main__':
    raise SystemExit(main())
