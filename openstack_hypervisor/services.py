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
from pathlib import Path

from snaphelpers import Snap

from openstack_hypervisor.log import setup_logging


class OpenStackService:
    """Base service object for OpenStack daemons."""

    conf_files = []
    conf_dirs = []

    executable = None

    def run(self, snap: Snap) -> int:
        """Runs the OpenStack service.

        Invoked when this service is started.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / f"{self.executable.name}-{snap.name}.log")

        args = []
        for conf_file in self.conf_files:
            args.extend(
                [
                    "--config-file",
                    str(snap.paths.common / conf_file),
                ]
            )
        for conf_dir in self.conf_dirs:
            args.extend(
                [
                    "--config-dir",
                    str(snap.paths.common / conf_dir),
                ]
            )

        executable = snap.paths.snap / self.executable

        cmd = [str(executable)]
        cmd.extend(args)
        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode


class NovaComputeService(OpenStackService):
    """A python service object used to run the nova-compute daemon."""

    conf_files = [
        Path("etc/nova/nova.conf"),
    ]
    conf_dirs = [
        Path("etc/nova/nova.conf.d"),
    ]

    executable = Path("usr/bin/nova-compute")


def nova_compute():
    """Main entry point for nova-compute."""
    service = NovaComputeService()
    exit_code = service.run(Snap())
    sys.exit(exit_code)


class NovaAPIMetadataService(OpenStackService):
    """A python service object used to run the nova-api-metadata daemon."""

    conf_files = [
        Path("etc/nova/nova.conf"),
    ]
    conf_dirs = [
        Path("etc/nova/nova.conf.d"),
    ]

    executable = Path("usr/bin/nova-api-metadata")


def nova_api_metadata():
    """Main entry point for nova-compute."""
    service = NovaAPIMetadataService()
    exit_code = service.run(Snap())
    sys.exit(exit_code)


class NeutronOVNMetadataAgentService(OpenStackService):
    """A python service object used to run the neutron-ovn-metadata-agent daemon."""

    conf_files = [
        Path("etc/neutron/neutron.conf"),
        Path("etc/neutron/neutron_ovn_metadata_agent.ini"),
    ]
    conf_dirs = [
        Path("etc/neutron/neutron.conf.d"),
    ]

    executable = Path("usr/bin/neutron-ovn-metadata-agent")


def neutron_ovn_metadata_agent():
    """Main entry point for neutron-ovn-metadata-agent."""
    service = NeutronOVNMetadataAgentService()
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
            f"--system-id={snap.config.get('node.fqdn')}",
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
