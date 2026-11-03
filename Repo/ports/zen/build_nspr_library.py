#!/usr/bin/env python3
"""Build NSPR and stream its output to one canonical, current log."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shlex
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--make', default='make')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    directory = ROOT / 'ports/zen/upstream/obj-gecko-alix/config/external/nspr/pr'
    log = ROOT / 'build/ports/zen/nspr-full-library-build.log'
    log.parent.mkdir(parents=True, exist_ok=True)
    command = [args.make, '-C', str(directory), '-j', str(args.jobs)]
    with log.open('w') as output:
        def emit(line):
            output.write(line)
            output.flush()
            sys.stdout.write(line)
            sys.stdout.flush()

        emit(f'NSPR_BUILD: started_utc={datetime.now(timezone.utc).isoformat()}\n')
        emit(f'NSPR_BUILD: command={shlex.join(command)}\n')
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1) as process:
            try:
                for line in process.stdout:
                    emit(line)
                status = process.wait()
            except KeyboardInterrupt:
                process.send_signal(signal.SIGINT)
                status = process.wait()
        status = status if status >= 0 else 128 - status
        emit(f'NSPR_BUILD: exit_status={status}\n')
    return status


if __name__ == '__main__':
    raise SystemExit(main())
