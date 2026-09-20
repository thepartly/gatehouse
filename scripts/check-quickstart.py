#!/usr/bin/env python3
"""Verify README parity and run its program as a standalone Cargo consumer."""

import argparse
import pathlib
import shutil
import subprocess
import tempfile
import tomllib

repository = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group()
mode.add_argument("--gatehouse-path", type=pathlib.Path, default=repository)
mode.add_argument("--released", action="store_true")
arguments = parser.parse_args()
fixture = repository / "tests/consumer/quickstart"
quickstart = (repository / "README.md").read_text().split("## Quick Start", 1)[1]
program = quickstart.split("```rust\n", 1)[1].split("```", 1)[0]
assert program == (fixture / "src/main.rs").read_text(), "README program differs from consumer"
dependencies = quickstart.split("```toml\n", 1)[1].split("```", 1)[0]
manifest = (fixture / "Cargo.toml").read_text()
version = tomllib.loads((arguments.gatehouse_path / "Cargo.toml").read_text())["package"]["version"]
published_dependencies = manifest.split("[dependencies]\n", 1)[1].replace(
    f'{{ version = "={version}", path = "../../.." }}', f'"={version}"'
)
assert dependencies == f"[dependencies]\n{published_dependencies}", "README dependencies differ from consumer"

with tempfile.TemporaryDirectory(prefix="gatehouse-quickstart-") as temporary:
    consumer = pathlib.Path(temporary) / "consumer"
    shutil.copytree(fixture, consumer, ignore=shutil.ignore_patterns("target"))
    if arguments.released:
        (consumer / "Cargo.lock").unlink()
        consumer_manifest = manifest.split("[dependencies]\n", 1)[0] + dependencies
    else:
        consumer_manifest = manifest.replace(
            'path = "../../.."', f'path = "{arguments.gatehouse_path.resolve().as_posix()}"'
        )
    (consumer / "Cargo.toml").write_text(consumer_manifest)
    command = ["cargo", "run", "--manifest-path", str(consumer / "Cargo.toml")]
    if not arguments.released:
        command.append("--locked")
    subprocess.run(command, check=True)
