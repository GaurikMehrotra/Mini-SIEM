"""Run one offline sensor at a time; docker cp supports remote cloud daemons."""

import argparse
import os
import subprocess
from pathlib import Path

IMAGES = {
    "zeek": "zeek/zeek:8.0.2@sha256:46dad84bfd94ebd5b76c6db7f5e2ccb2327fb3a78885dbb6dd3ff06517da1f6b",
    "suricata": "jasonish/suricata:8.0.2@sha256:8265743d05e225ed0a83c9223ec25fb2eeb019098e1f3d0c5d53a1db4d4d3559",
}
ROOT = Path(__file__).resolve().parents[2]


def run(sensor: str, pcap: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Output directory must be empty to preserve prior results")
    command = (
        ["/bin/sh", "-c", "cd /output && exec zeek -r /input.pcap /config.zeek"]
        if sensor == "zeek"
        else [
            "suricata",
            "-c",
            "/config.yaml",
            "-r",
            "/input.pcap",
            "-l",
            "/output",
            "-S",
            "/local.rules",
            "--runmode",
            "single",
            "--set",
            "outputs.1.eve-log.community-id=true",
        ]
    )
    cid = subprocess.check_output(
        [
            "docker",
            "create",
            "--network",
            "none",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--workdir",
            "/",
            "--entrypoint",
            command[0],
            IMAGES[sensor],
            *command[1:],
        ],
        text=True,
    ).strip()
    try:
        subprocess.run(
            ["docker", "cp", "-a", str(destination.resolve()), cid + ":/output"], check=True
        )
        subprocess.run(["docker", "cp", str(pcap.resolve()), cid + ":/input.pcap"], check=True)
        config = ROOT / "lab/sensors" / ("zeek.zeek" if sensor == "zeek" else "local.rules")
        subprocess.run(
            [
                "docker",
                "cp",
                str(config),
                cid + (":/config.zeek" if sensor == "zeek" else ":/local.rules"),
            ],
            check=True,
        )
        if sensor == "suricata":
            subprocess.run(
                ["docker", "cp", str(ROOT / "lab/sensors/suricata.yaml"), cid + ":/config.yaml"],
                check=True,
            )
        if sensor == "suricata":
            for filename in ("classification.config", "reference.config", "threshold.config"):
                subprocess.run(
                    ["docker", "cp", str(ROOT / "lab/sensors" / filename), cid + ":/" + filename],
                    check=True,
                )
        subprocess.run(["docker", "start", "-a", cid], check=True)
        status = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.ExitCode}}", cid], text=True
        ).strip()
        if status != "0":
            raise RuntimeError("sensor exited " + status)
        subprocess.run(["docker", "cp", cid + ":/output/.", str(destination.resolve())], check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("sensor", choices=sorted(IMAGES))
    p.add_argument("pcap", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    run(a.sensor, a.pcap, a.destination)
