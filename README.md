# MicroStack Hypervisor Snap

This repository contains the source for the the MicroStack Hypervisor snap.

This snap is designed to be used with a deployed OpenStack Control plane such
as delivered by Sunbeam.

## Getting Started

To get started with the MicroStack Hypervisor, install the snap using snapd:

```bash
$ sudo snap install microstack-hypervisor
```

The snap needs to be configured with credentials and URL's for the Identity
service of the OpenStack cloud that it will form part of - for example:

```bash
$ sudo snap set microstack-hypervisor \
    identity.auth_url=http://10.64.140.43:80/sunbeam-keystone \
    identity.username=nova-hypervisor-01 \
    identity.password=supersecure21
```

it's also possible to configure domain and project configuration.

The snap also needs to be configured with access to RabbitMQ:

```bash
$ sudo snap set microstack-hypervisor \
    rabbitmq.url=rabbit://nova:supersecure22@10.152.183.212:5672/openstack
```

and with URL's for access to Network services:

```bash
$ sudo snap set microstack-hypervisor \
    network.url=http://10.64.140.43:80/sunbeam-neutron \
    network.ovn-sb-connection=tcp:10.152.183.220:6642 \
    network.ovn-sb-connection=tcp:10.152.183.220:6643
```

The snap has numerous other configuration options - see "Configuration Reference"
for full details.

## Configuration Reference

### compute

Configuration of options related to compute (Nova):

* `compute.virt-type`

Virtualization type libvirt should use; this is runtime detected
by the snap and will be set to `kvm` if the host is capable of
full virtualization or `qemu` if not.

* `compute.cpu-mode` (`host-model`) CPU mode for instances

Valid values: `host-model`, `host-passthrough`, `custom`, `none`.

* `compute.cpu-models`

An ordered list of CPU models the host supports.

Only used with `compute.cpu-mode` is set to `custom`.

For more details please refer to the Nova [configuration reference][https://docs.openstack.org/nova/latest/admin/cpu-models.html] for cpu models.

* `compute.spice-proxy-address` (`localhost`)

IP address to use for configuration of SPICE consoles in instances.

### identity

Configuration of options related to identity (Keystone):

* `identity.auth-url` Full URL for Keystone API
* `identity.username` Username for services to use
* `identity.password` Password for services to use
* `identity.user-domain-name` (`service_domain`) Domain for user
* `identity.project-name` (`services`) Service project
* `identity.project-domain-name` (`service_domain`) Domain for service project
* `identity.region-name` (`RegionOne`) OpenStack region to use

### logging

Configuration of logging options across all services:

* `logging.debug` (`false`) Enable debug log level

### node

Configuration of options related to the hypervisor node in general:

* `node.fqdn` (`hostname -f`) Fully qualified hostname for node
* `node.ip-address` IP address to use for service configuration

These options are use to configure the identity of the agents that
run as part of the snap.

### network

Configuration of options related to networking, including Neutron
and OVN:

* `network.dns-domain` DNS domain name to use for networking
* `network.dns-servers` External DNS servers to use for forwarding DNS requests
* `network.external-bridge` (`br-ex`)  Name of OVS external network bridge
* `network.ip-address` IP address to use for overlay network endpoints
* `network.ovn-nb-connection` (`tcp:127.0.0.1:6642`) OVN Northbound DB connection URL
* `network.ovn-sb-connection` (`tcp:127.0.0.1:6642`) OVN Southbound DB connection URL
* `network.physnet-name` (`physnet1`) Neutron label for physical network
* `network.url` Full URL for Neutron API

### rabbitmq

Configuration of options related to RabbitMQ messaging:

* `rabbitmq.url` (`rabbit://localhost:5672`) Full connection URL to RabbitMQ

## Build

The build and test with this snap see CONTRIBUTING.md.