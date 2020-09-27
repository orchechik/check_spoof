# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# This plugin only works on Windows 8+

import logging
from typing import List

from volatility.framework import constants, exceptions, renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.plugins.windows import pslist, poolscanner

vollog = logging.getLogger(__name__)


class Check_parent_spoof(interfaces.plugins.PluginInterface):
    """Lists process command line arguments."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]

    def _generator(self, procs):

        conhost_pids = []
        appinfo_service_pid = 0
        suspicious_procs = {}
        
        # For unknown reasons, the owner process id will point to the actual parent id + 2 with the exception of conhost which is +1.
        # OWNER_PROCESS_ID_OFFSET will be used to get the real parent PID from the OwnerProcessId field.
        OWNER_PROCESS_ID_OFFSET = -2
        # CONHOST_PROCESS_ID_OFFSET will be used to check if OwnerProcessId actually points to a console host process.
        CONHOST_PROCESS_ID_OFFSET = -1
        
        # OwnerProcessId only exists as a union from Windows 8 or later.
        is_win8_or_later = poolscanner.os_distinguisher(version_check=lambda x: x >= (6, 2),
                                                         fallback_checks=[("_EPROCESS", "OwnerProcessId", True)])
        if not is_win8_or_later(self.context, self.config["nt_symbols"]):
            vollog.warning("check_parent_spoof doesn't work in Windows versions prior to Windows 8")
            return

        for proc in procs:
            if not proc.has_member("OwnerProcessId"):
                continue
            process_name = utility.array_to_string(proc.ImageFileName)
            inherited_process_pid = proc.InheritedFromUniqueProcessId

            # Save appinfo's service pid to exclude, this is hosted only by svchost.exe.
            if (appinfo_service_pid == 0) and ("svchost" in process_name):
                for entry in proc.load_order_modules():
                    dll_name = renderers.UnreadableValue()
                    try:
                        dll_name = entry.FullDllName.get_string()
                        if "appinfo.dll" not in dll_name:
                            continue

                    except exceptions.InvalidAddressException:
                        continue

                    appinfo_service_pid = proc.UniqueProcessId

                    # If a process was already flagged as suspicious and it's actually pointing to the appinfo service, it should not be flagged.
                    if proc.UniqueProcessId in suspicious_procs:
                        suspicious_procs.pop(proc.UniqueProcessId)

            # The Owner process id field is used a union for the owner process id and console host process id
            # We save the conhost process id's in order to exclude them from the check.
            if "conhost" in process_name:
                conhost_pids.append(proc.UniqueProcessId)

                # If a process was already flagged as suspicious and it's actually pointing to a conhost process, it should not be flagged.
                # Since suspicious_procs saves everything at OWNER_PROCESS_ID_OFFSET we correct the offset check here by adding the conhost offset.
                conhost_pid = proc.UniqueProcessId + CONHOST_PROCESS_ID_OFFSET
                if conhost_pid in suspicious_procs:
                    suspicious_procs.pop(conhost_pid)

            try:
                owner_process_pid = proc.OwnerProcessId

                # There are several checks here:
                # Most services and system processes are initialized with 0, exclude them and System by checking if the pid is under 0.
                # AppInfo service is responsible for UAC and could be triggered as a false positive as well.
                if (owner_process_pid < 10) or (owner_process_pid + OWNER_PROCESS_ID_OFFSET == inherited_process_pid) \
                        or (owner_process_pid + OWNER_PROCESS_ID_OFFSET == appinfo_service_pid) or (owner_process_pid + CONHOST_PROCESS_ID_OFFSET) in conhost_pids:
                    continue

            except Exception as e:
                continue

            suspicious_procs[owner_process_pid + OWNER_PROCESS_ID_OFFSET] = (proc.UniqueProcessId, process_name, inherited_process_pid, owner_process_pid + OWNER_PROCESS_ID_OFFSET)

        for owner_process_id, suspicious_proc in suspicious_procs.items():
            yield (0, (suspicious_proc[0], suspicious_proc[1], suspicious_proc[2], suspicious_proc[3]))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Inherited PPID", int), ("Owner PPID", int)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
