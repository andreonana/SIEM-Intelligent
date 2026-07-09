"""
Schémas de requêtes/réponses.

Point critique de sécurité : toute IP reçue est validée avec le module
`ipaddress` de la stdlib AVANT d'atteindre le moindre subprocess. Une IP
qui ne parse pas est rejetée avec 422, jamais transmise à un shell.
"""
import ipaddress
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address
from typing import Optional

from pydantic import BaseModel, Field, field_validator

UNBLOCKABLE_IPV4_VALUES = {
    IPv4Address("0.0.0.0"),
    IPv4Address("255.255.255.255"),
}


def validate_supported_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"'{value}' n'est pas une adresse IP valide")

    if ip.version != 4:
        raise ValueError("IPv6 n'est pas encore supporte par l'agent firewall actuel")

    return str(ip)


def validate_blockable_ipv4(value: str) -> str:
    normalized = validate_supported_ipv4(value)
    ip = ipaddress.ip_address(normalized)

    if (
        ip in UNBLOCKABLE_IPV4_VALUES
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_link_local
        or ip.is_reserved
    ):
        raise ValueError(f"'{value}' est une adresse systeme/non bloquable")

    return normalized


class ActionMode(str, Enum):
    AUTO = "auto"        # exécution immédiate (ex: IP attaquante externe)
    CONFIRM = "confirm"  # délai avant exécution, annulable (ex: machine interne)


class BlockRequest(BaseModel):
    attacker_ip: str = Field(..., description="IP à bloquer immédiatement (mode AUTO)")
    victim_ip: Optional[str] = Field(
        None, description="IP de la machine source/victime à isoler (souvent mode CONFIRM)"
    )
    incident_id: str = Field(..., description="Identifiant de l'incident SIEM pour traçabilité")
    rule_id: Optional[str] = Field(None, description="ID de la règle de corrélation ayant déclenché l'action")
    reason: str = Field(..., description="Justification humaine, pour l'audit")
    victim_mode: ActionMode = Field(
        default=ActionMode.CONFIRM,
        description="Mode d'exécution pour le blocage de la victim_ip",
    )

    @field_validator("attacker_ip", "victim_ip")
    @classmethod
    def must_be_valid_ip(cls, v):
        if v is None:
            return v
        return validate_blockable_ipv4(v)


class UnblockRequest(BaseModel):
    ip: str
    incident_id: str
    reason: str

    @field_validator("ip")
    @classmethod
    def must_be_valid_ip(cls, v):
        return validate_supported_ipv4(v)


class BlockedEntry(BaseModel):
    ip: str
    blocked_at: datetime
    incident_id: str
    rule_id: Optional[str] = None
    reason: str


class PendingConfirmEntry(BaseModel):
    action_id: str
    ip: str
    incident_id: str
    reason: str
    scheduled_at: datetime
    executes_at: datetime


class ActionResult(BaseModel):
    status: str  #statut peut avoir différente valeurs : "executed" | "scheduled" | "cancelled" | "already_blocked" | "not_found"
    ip: Optional[str] = None
    action_id: Optional[str] = None
    detail: str


class BlockResponse(BaseModel):
    results: list[ActionResult]
