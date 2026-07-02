from __future__ import annotations

from typing import Iterable, List, Optional

from . import console
from .cracking import CredentialRecord


def _infer_domain(records: Iterable[CredentialRecord]) -> str:
    for record in records:
        if record.domain:
            return record.domain.upper()
    return ""


def mark_owned(
    records: Iterable[CredentialRecord],
    uri: str,
    user: str,
    password: str,
) -> None:
    try:
        from neo4j import GraphDatabase, basic_auth
        from neo4j.exceptions import AuthError, ServiceUnavailable
    except ImportError:
        console.error("The 'neo4j' package is required for -bh. Install revealhashed with its dependencies.")
        return

    records = list(records)
    if not records:
        console.warn("No accounts to mark in BloodHound.")
        return

    fallback_domain = _infer_domain(records)

    try:
        driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
        driver.verify_connectivity()
    except AuthError:
        console.error(f"Authentication failed for BloodHound Neo4j at {uri}")
        return
    except ServiceUnavailable:
        console.error(f"BloodHound DB unreachable at {uri}")
        return
    except Exception as exc:
        console.error(f"Could not connect to BloodHound Neo4j: {exc}")
        return

    print()
    console.info(f"Connected to BloodHound Neo4j at {uri} as {user}")

    try:
        with driver.session() as session:
            for record in records:
                _mark_single(session, record, fallback_domain)
    except Exception as exc:
        console.error(f"Error while marking BloodHound: {exc}")
    finally:
        driver.close()


def _mark_single(session, record: CredentialRecord, fallback_domain: str) -> None:
    label = "Computer" if record.is_computer else "User"
    account = record.account.upper()
    domain = (record.domain or fallback_domain).upper()

    if domain:
        name = f"{account}.{domain}" if record.is_computer else f"{account}@{domain}"
        query = (
            f"MATCH (n:{label}) WHERE toUpper(n.name) = $name "
            "SET n.owned = true RETURN n.name AS name"
        )
        params = {"name": name}
        label_name = name
    else:
        prefix = f"{account}." if record.is_computer else f"{account}@"
        query = (
            f"MATCH (n:{label}) WHERE toUpper(n.name) STARTS WITH $prefix "
            "SET n.owned = true RETURN n.name AS name"
        )
        params = {"prefix": prefix}
        label_name = f"{account}{'.' if record.is_computer else '@'}*"

    result = session.run(query, **params).data()
    if not result:
        console.miss(f"Node {label_name} not found in BloodHound")
        return
    for row in result:
        console.info(f"Marked {row['name']} as owned in BloodHound")
