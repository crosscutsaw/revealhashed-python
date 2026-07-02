from __future__ import annotations

from dataclasses import dataclass
from getpass import getpass
from typing import Optional


@dataclass
class Target:
    domain: str
    username: str
    password: str
    host: str
    lmhash: str = ""
    nthash: str = ""
    aes_key: Optional[str] = None
    dc_ip: Optional[str] = None
    do_kerberos: bool = False

    @property
    def ntlm_hashes(self) -> str:
        return f"{self.lmhash}:{self.nthash}"

    @classmethod
    def from_options(cls, options) -> "Target":
        from impacket.examples.utils import parse_target

        domain, username, password, host = parse_target(options.target)
        domain = domain or ""

        hashes = getattr(options, "hashes", None)
        no_pass = getattr(options, "no_pass", False)
        do_kerberos = getattr(options, "k", False)
        aes_key = getattr(options, "aesKey", None)

        lmhash = nthash = ""
        if hashes:
            if ":" in hashes:
                lmhash, nthash = hashes.split(":", 1)
            else:
                nthash = hashes

        need_password = (
            not password
            and username
            and not hashes
            and not aes_key
            and not do_kerberos
            and not no_pass
        )
        if need_password:
            password = getpass("Password: ")

        dc_ip = getattr(options, "dc_ip", None) or host

        return cls(
            domain=domain,
            username=username[:20],
            password=password,
            host=host,
            lmhash=lmhash,
            nthash=nthash,
            aes_key=aes_key,
            dc_ip=dc_ip,
            do_kerberos=do_kerberos,
        )


def connect_smb(target: Target):
    from impacket.smbconnection import SMBConnection

    smb = SMBConnection(target.host, target.host)
    if target.do_kerberos:
        smb.kerberosLogin(
            user=target.username,
            password=target.password,
            domain=target.domain,
            lmhash=target.lmhash,
            nthash=target.nthash,
            aesKey=target.aes_key,
            kdcHost=target.dc_ip,
        )
    else:
        smb.login(
            user=target.username,
            password=target.password,
            domain=target.domain,
            lmhash=target.lmhash,
            nthash=target.nthash,
        )
    return smb
