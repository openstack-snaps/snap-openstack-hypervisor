#!/usr/bin/env python3

import os
import socket

from init import shell
from init import credentials


def _get_default_config():
    snap_common = os.getenv('SNAP_COMMON')
    return {
        'config.is-clustered': False,

        'config.cluster.tls-cert-path':
        f'{snap_common}/etc/cluster/tls/cert.pem',
        'config.cluster.tls-key-path':
        f'{snap_common}/etc/cluster/tls/key.pem',

        'config.cluster.fingerprint': 'null',
        'config.cluster.hostname': 'null',
        'config.cluster.credential-id': 'null',
        'config.cluster.credential-secret': 'null',

        'config.post-setup': True,
        'config.keystone.region-name': 'microstack',
        'config.credentials.key-pair': '/home/{USER}/snap/{SNAP_NAME}'
                                       '/common/.ssh/id_microstack',
        'config.network.node-fqdn': socket.getfqdn(),
        'config.network.dns-servers': '1.1.1.1',
        'config.network.dns-domain': 'microstack.example.',
        'config.network.ext-gateway': '10.20.20.1',
        'config.network.control-ip': '10.20.20.1',
        'config.network.compute-ip': '10.20.20.1',
        'config.network.ext-cidr': '10.20.20.1/24',
        'config.network.security-rules': True,
        'config.network.dashboard-allowed-hosts': '*',
        'config.network.ports.dashboard': 443,
        'config.network.ports.mysql': 3306,
        'config.network.ports.rabbit': 5672,
        'config.network.external-bridge-name': 'br-ex',
        'config.network.physnet-name': 'physnet1',
        'config.cinder.setup-loop-based-cinder-lvm-backend': False,
        'config.cinder.loop-device-file-size': '32G',
        'config.cinder.lvm-backend-volume-group': 'cinder-volumes',
        'config.host.ip-forwarding': False,
        'config.host.check-qemu': True,
        'config.services.control-plane': True,
        'config.services.hypervisor': True,
        'config.services.spice-console': True,
        'config.cluster.role': 'control',
        'config.cluster.password': 'null',
        'config.cleanup.delete-bridge': True,
        'config.cleanup.remove': True,
        'config.logging.custom-config': f'{snap_common}/etc/filebeat'
                                        '/filebeat-microstack.yaml',
        'config.logging.datatag': '',
        'config.logging.debug': False,
        'config.logging.host': 'localhost:5044',
        'config.services.extra.enabled': False,
        'config.services.extra.filebeat': False,
        'config.alerting.custom-config': f'{snap_common}/etc/nrpe'
                                         '/nrpe-microstack.cfg',
        'config.services.extra.nrpe': False,
        'config.monitoring.ipmi': '',
        'config.services.extra.telegraf': False,
        'config.monitoring.custom-config': f'{snap_common}/etc/telegraf'
                                           '/telegraf-microstack.conf',

        # Use emulation by default (with an option to override if KVM is
        # supported).
        'config.nova.virt-type': 'qemu',
        # Use a host CPU model so that any CPU features enabled for
        # vulnerability mitigation are enabled.
        'config.nova.cpu-mode': 'host-model',
        # Do not override cpu-models by default.
        'config.nova.cpu-models': '',

        'config.tls.generate-self-signed': True,
        'config.tls.cacert-path':
        f'{snap_common}/etc/ssl/certs/cacert.pem',
        'config.tls.cert-path':
        f'{snap_common}/etc/ssl/certs/cert.pem',
        'config.tls.key-path':
        f'{snap_common}/etc/ssl/private/key.pem',
        'config.tls.compute.cert-path':
        f'{snap_common}/etc/ssl/certs/compute-cert.pem',
        'config.tls.compute.key-path':
        f'{snap_common}/etc/ssl/private/compute-key.pem',
    }


def _set_default_config():
    shell.config_set(**_get_default_config())


def _setup_secrets():
    # If a user runs init multiple times we do not want to generate
    # new credentials to keep the init operation idempotent.
    existing_creds = shell.config_get('config.credentials')
    if isinstance(existing_creds, dict):
        existing_cred_keys = existing_creds.keys()
    else:
        existing_cred_keys = []
    shell.config_set(**{
        f'config.credentials.{k}': credentials.generate_password() for k in [
            'mysql-root-password',
            'rabbitmq-password',
            'keystone-password',
            'nova-password',
            'cinder-password',
            'neutron-password',
            'placement-password',
            'glance-password',
            'ovn-metadata-proxy-shared-secret',
        ] if k not in existing_cred_keys
    })


if __name__ == '__main__':
    _set_default_config()
    _setup_secrets()
