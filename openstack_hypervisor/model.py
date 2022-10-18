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

from pydantic import AnyUrl, BaseModel, Field, IPvAnyAddress
from typing import Optional


class RabbitMQUrl(AnyUrl):
    allowed_schemes = {'rabbit', 'amqp'}
    host_required = True


class IdentityServiceConfig(BaseModel):
    """Data Model for Keystone Identity settings for the hypervisor services.
    """
    auth_url: Optional[AnyUrl] = Field(alias='auth-url', default=None)
    username: Optional[str]
    password: Optional[str]
    user_domain_name: Optional[str] = Field(
        alias='user-domain-name', default='service_domain',
    )
    project_name: Optional[str] = Field(
        alias='project-name', default='services',
    )
    project_domain_name: Optional[str] = Field(
        alias='project-domain-name', default='service_domain',
    )
    region_name: Optional[str] = Field(
        alias='region-name', default='RegionOne',
    )


class RabbitMQConfig(BaseModel):
    """Data Model for RabbitMQ configuration settings."""
    url: RabbitMQUrl = Field(
        alias="url", default="rabbit://localhost:5672",
    )


class ComputeConfig(BaseModel):
    """Data Model for Nova configuration settings."""
    cpu_mode: str = Field(alias="cpu-mode", default="host-model")
    virt_type: str = Field(alias="virt-type", default="auto")
    cpu_models: Optional[str] = Field(alias="cpu-models")
    spice_proxy_address: Optional[IPvAnyAddress] = Field(
        alias="spice-proxy-address"
    )


class NetworkConfig(BaseModel):
    """Data Model for network configuration settings."""
    physnet_name: str = Field(alias="physnet-name", default="physnet1")
    external_bridge: str = Field(alias="external-bridge", default="br-ex")
    dns_domain = Field(alias="dns-domain", default="openstack.local")
    dns_servers: IPvAnyAddress = Field(alias="dns-servers", default="8.8.8.8")
    ovn_sb_connection: str = Field(
        alias="ovn-sb-connection", default="tcp:127.0.0.1:6642"
    )
    enable_gateway: bool = Field(
        alias="enable-gateway", default=False
    )
    ip_address: Optional[IPvAnyAddress] = Field(alias="network.ip-address")


class NodeConfig(BaseModel):
    """Data model for the node configuration settings."""
    fqdn: Optional[str]
    ip_address: Optional[IPvAnyAddress] = Field(alias="ip-address")


class LoggingConfig(BaseModel):
    """Data model for the logging configuration for the hypervisor."""
    debug: bool = Field(default=False)
