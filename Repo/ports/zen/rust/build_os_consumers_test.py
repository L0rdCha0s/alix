#!/usr/bin/env python3
"""Build Gecko logging, storage, errno and process-service native packages."""
from gecko_fixture import run

if __name__ == "__main__":
    run("os-consumers")
