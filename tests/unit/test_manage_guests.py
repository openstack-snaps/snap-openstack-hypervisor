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

import pytest

from openstack_hypervisor import manage_guests


class TestManageGuests:
    """Contains tests for openstack_hypervisor.manage_guests."""

    def test_openstack_guest(self):
        with open("tests/unit/virsh_openstack.xml", "r") as f:
            assert manage_guests.openstack_guest(f.read())
        with open("tests/unit/virsh_non_openstack.xml", "r") as f:
            assert not manage_guests.openstack_guest(f.read())

    def test_running_guests(self, mocker, libvirt, vms):
        assert manage_guests.running_guests(list(vms.values())) == [vms["vm1"], vms["vm2"]]

    def test_delete_openstack_guests(self, mocker, libvirt, sleep, vms):
        conn_mock = mocker.Mock()
        libvirt.open.return_value = conn_mock
        conn_mock.listAllDomains.return_value = list(vms.values())
        manage_guests.delete_openstack_guests()
        assert not vms["vm1"].isActive()
        # vm2 is not an openstack vm so should not have been shutdown
        assert vms["vm2"].isActive()
        assert not vms["vm3"].isActive()

    def test_delete_openstack_guests_timeout(self, mocker, libvirt, sleep, vms):
        conn_mock = mocker.Mock()
        libvirt.open.return_value = conn_mock
        conn_mock.listAllDomains.return_value = list(vms.values())
        # Stop VM1 responding to shutdown requests
        vms["vm1"].destroy.side_effect = lambda: None
        with pytest.raises(TimeoutError):
            manage_guests.delete_openstack_guests()
