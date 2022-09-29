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
import os
import secrets
import socket
import string
import subprocess
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, Template
from snaphelpers import Snap

from microstack_hypervisor.log import setup_logging

UNSET = ""

DEFAULT_CONFIG = {
    # Keystone
    "identity.auth-url": "http://localhost:5000/v3",
    "identity.username": UNSET,
    "identity.password": UNSET,
    # keystone-k8s defaults
    "identity.user-domain-name": "service_domain",
    "identity.project-name": "services",
    "identity.project-domain-name": "service_domain",
    "identity.region-name": "RegionOne",
    # Messaging
    "rabbitmq.url": "rabbit://localhost:5672",
    # Nova
    "compute.cpu-mode": "host-model",
    "compute.virt-type": "qemu",
    "compute.cpu-models": UNSET,
    "compute.spice-proxy-address": "localhost",
    # Neutron
    "network.url": "http://localhost:9696",
    "network.physnet-name": "physnet1",
    "network.external-bridge": "br-ex",
    "network.dns-domain": "openstack.local",
    "network.dns-servers": "8.8.8.8",
    "network.ovn-nb-connection": "tcp:127.0.0.1:6642",
    "network.ovn-sb-connection": "tcp:127.0.0.1:6642",
    "network.ip-address": UNSET,
    # General
    "logging.debug": False,
    "node.fqdn": socket.getfqdn(),
    "node.ip-address": UNSET,
    # TLS
}

SECRETS = ["credentials.ovn-metadata-proxy-shared-secret"]

DEFAULT_SECRET_LENGTH = 32

# NOTE(dmitriis): there is currently no way to make sure this directory gets
# recreated on reboot which would normally be done via systemd-tmpfiles.
# mkdir -p /run/lock/snap.$SNAP_INSTANCE_NAME

# Copy TEMPLATE.qemu into the common directory. Libvirt generates additional
# policy dynamically which is why its apparmor directory is writeable under $SNAP_COMMON.
# Also copy other abstractions that are used by this template.
# rsync -rh $SNAP/etc/apparmor.d $SNAP_COMMON/etc

COMMON_DIRS = [
    # etc
    Path("etc/openvswitch"),
    Path("etc/ovn"),
    Path("etc/libvirt"),
    Path("etc/nova"),
    Path("etc/nova/nova.conf.d"),
    Path("etc/neutron"),
    Path("etc/neutron/neutron.conf.d"),
    # log
    Path("log/libvirt/qemu"),
    Path("log/ovn"),
    Path("log/openvswitch"),
    Path("log/nova"),
    Path("log/neutron"),
    # run
    Path("run/ovn"),
    Path("run/openvswitch"),
    # lock
    Path("lock"),
]

DATA_DIRS = [
    Path("lib/libvirt/images"),
    Path("lib/ovn"),
    Path("lib/nova/instances"),
    Path("lib/neutron"),
]


def _generate_secret(length: int = DEFAULT_SECRET_LENGTH) -> str:
    """Generate a secure secret.

    :param length: length of generated secret
    :type length: int
    :return: string containing the generated secret
    """
    return "".join(secrets.choice(string.ascii_letters + string.digits) for i in range(length))


def _mkdirs(snap: Snap) -> None:
    """Ensure directories requires for operator of snap exist.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    for dir in COMMON_DIRS:
        os.makedirs(snap.paths.common / dir, exist_ok=True)
    for dir in DATA_DIRS:
        os.makedirs(snap.paths.data / dir, exist_ok=True)


def _setup_secrets(snap: Snap) -> None:
    """Setup any secrets needed for snap operation.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    credentials = snap.config.get_options("credentials")

    for secret in SECRETS:
        if not credentials.get(secret):
            snap.config.set({secret: _generate_secret()})


def install(snap: Snap) -> None:
    """Runs the 'install' hook for the snap.

    The 'install' hook will create the configuration directory, located
    at $SNAP_COMMON/etc and set the default configuration options.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    setup_logging(snap.paths.common / "hooks.log")
    logging.info("Running install hook")
    logging.info(f"Setting default config: {DEFAULT_CONFIG}")
    snap.config.set(DEFAULT_CONFIG)


def _get_template(snap: Snap, template: str) -> Template:
    """Returns the Jinja2 template to render.

    Locates the jinja template within the snap to load and returns
    the Template to the caller. This will look for the template in
    the 'templates' directory of the snap.

    :param snap: the snap to provide context
    :type snap: Snap
    :param template: the name of the template to locate
    :type template: str
    :return: the Template to use to render.
    :rtype: Template
    """
    template_dir = snap.paths.snap / "templates"
    env = Environment(loader=FileSystemLoader(searchpath=str(template_dir)))
    return env.get_template(template)


def _context_compat(context: Dict[str, Any]) -> Dict[str, Any]:
    """Manipulate keys in context to be Jinja2 template compatible.

    Jinja2 templates using dot notation need to have Python compatible
    keys; '_' is not accepted in a key name for snapctl so we have to use
    '-' instead.  Remap these back to '_' for template usage.

    :return: dictionary in Jinja2 compatible format
    :rtype: Dict
    """
    clean_context = {}
    for key, value in context.items():
        key = key.replace("-", "_")
        if not isinstance(value, Dict):
            clean_context[key] = value
        else:
            clean_context[key] = _context_compat(value)
    return clean_context


TEMPLATES = {
    Path("etc/nova/nova.conf"): "nova.conf.j2",
    Path("etc/neutron/neutron.conf"): "neutron.conf.j2",
    Path("etc/neutron/neutron_ovn_metadata_agent.ini"): "neutron_ovn_metadata_agent.ini.j2",
    Path("etc/libvirt/libvirtd.conf"): "libvirtd.conf.j2",
    Path("etc/libvirt/qemu.conf"): "qemu.conf.j2",
    Path("etc/libvirt/virtlogd.conf"): "virtlogd.conf.j2",
}


def _update_default_config(snap: Snap) -> None:
    """Add any missing default configuration keys.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    option_keys = set([k.split(".")[0] for k in DEFAULT_CONFIG.keys()])
    current_options = snap.config.get_options(*option_keys)
    for option, default in DEFAULT_CONFIG.items():
        if option not in current_options:
            snap.config.set({option: default})


def _configure_ovn(snap: Snap) -> None:
    """Configure OVS/OVN.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    # Check for network specific IP address
    ovn_encap_ip = snap.config.get("network.ip-address")
    if not ovn_encap_ip:
        # Fallback to general node IP
        ovn_encap_ip = snap.config.get("node.ip-address")
    system_id = snap.config.get("node.fqdn")
    if not ovn_encap_ip and system_id:
        logging.info("OVN IP and System ID not configured, skipping.")
        return
    logging.info(
        "Configuring Open vSwitch geneve tunnels and system id. "
        f"ovn-encap-ip = {ovn_encap_ip}, system-id = {system_id}"
    )
    subprocess.check_call(
        [
            "ovs-vsctl",
            "--retry",
            "set",
            "open",
            ".",
            "external-ids:ovn-encap-type=geneve",
            "--",
            "set",
            "open",
            ".",
            f"external-ids:ovn-encap-ip={ovn_encap_ip}",
            "--",
            "set",
            "open",
            ".",
            f"external-ids:system-id={system_id}",
        ]
    )
    sb_conn = snap.config.get("network.ovn-sb-connection")
    if not sb_conn:
        logging.info("OVN SB connection URL not configured, skipping.")
        return
    subprocess.check_call(
        ["ovs-vsctl", "--retry", "set", "open", ".", f"external-ids:ovn-remote={sb_conn}"]
    )


def configure(snap: Snap) -> None:
    """Runs the `configure` hook for the snap.

    This method is invoked when the configure hook is executed by the snapd
    daemon. The `configure` hook is invoked when the user runs a sudo snap
    set microstack-hypervisor.<foo> setting.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    setup_logging(snap.paths.common / "hooks.log")
    logging.info("Running configure hook")

    _mkdirs(snap)
    _update_default_config(snap)
    _setup_secrets(snap)

    context = snap.config.get_options(
        "compute",
        "network",
        "identity",
        "logging",
        "node",
        "rabbitmq",
        "credentials",
    ).as_dict()

    # Add some general snap path information
    context.update(
        {
            "snap_common": str(snap.paths.common),
            "snap_data": str(snap.paths.data),
            "snap": str(snap.paths.snap),
        }
    )
    context = _context_compat(context)
    logging.info(context)

    for config_file, template in TEMPLATES.items():
        template = _get_template(snap, template)
        config_file = snap.paths.common / config_file
        logging.info(f"Rendering {config_file}")
        try:
            output = template.render(context)
            with open(config_file, "w+") as f:
                f.write(output)
        except:  # noqa
            logging.exception(
                "An error occurred when attempting to render the mysql configuration file."
            )
            raise

    _configure_ovn(snap)
