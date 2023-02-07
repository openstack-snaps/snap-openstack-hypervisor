# Copyright 2023 Canonical Ltd.
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

import time
import xml.etree.ElementTree

import libvirt


def openstack_guest(guest_xml: str) -> bool:
    """Check if guest is managed by OpenStack."""
    ns = {"nova": "http://openstack.org/xmlns/libvirt/nova/1.1"}
    root = xml.etree.ElementTree.fromstring(guest_xml)
    metadata = root.findall("metadata")
    return bool([e.findall("nova:instance", ns) for e in metadata])


def running_guests(guests) -> list:
    """Extract list of running domains from provided list."""
    running = [dom for dom in guests if dom.isActive()]
    return running


def delete_openstack_guests() -> None:
    """Delete any guests managed by openstack."""
    conn = libvirt.open("qemu:///system")
    openstack_guests = [dom for dom in conn.listAllDomains() if openstack_guest(dom.XMLDesc())]
    for dom in running_guests(openstack_guests):
        try:
            dom.destroy()
        except libvirt.libvirtError as e:
            if "domain is not running" in e.get_error_message():
                pass
            else:
                raise

    for i in range(0, 150):
        if not running_guests(openstack_guests):
            break
        time.sleep(0.2)
    else:
        raise TimeoutError("Some guests not shutdown")
    for dom in openstack_guests:
        dom.undefine()
