# Copyright 2022 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import subprocess
import sys

from snaphelpers import Snap

from microstack_hypervisor.log import setup_logging


class NovaComputeService:
    """A python service object used to run the nova-compute daemon."""

    def run(self, snap: Snap) -> int:
        """Runs the nova-compute service.

        Invoked when this service is started.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / f"nova-compute-{snap.name}.log")
        etc_nova = snap.paths.common / "etc" / "nova"
        etc_nova_conf = etc_nova / "nova.conf"
        if not etc_nova_conf.exists():
            logging.warn(f"{etc_nova_conf} not found, skipping execution")
            return 0

        args = [
            "--config-file",
            str(etc_nova_conf),
            "--config-dir",
            str(etc_nova / "nova.conf.d"),
        ]
        executable = snap.paths.snap / "usr" / "bin" / "nova-compute"

        cmd = [str(executable)]
        cmd.extend(args)
        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode


def nova_compute():
    """Main entry point for nova-compute."""
    service = NovaComputeService()
    exit_code = service.run(Snap())
    sys.exit(exit_code)


class OVSDBServerService:
    """A python service object used to run the ovsdb-server daemon."""

    def run(self, snap: Snap) -> int:
        """Runs the ovsdb-server service.

        Invoked when this service is started.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / f"ovsdb-server-{snap.name}.log")

        executable = snap.paths.snap / "usr" / "share" / "openvswitch" / "scripts" / "ovs-ctl"
        args = [
            "--no-ovs-vswitchd",
            "--no-monitor",
            "--system-id=random",
            "start",
        ]
        cmd = [str(executable)]
        cmd.extend(args)

        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode


def ovsdb_server():
    """Main entry point for ovsdb-server."""
    service = OVSDBServerService()
    exit_code = service.run(Snap())
    sys.exit(exit_code)
