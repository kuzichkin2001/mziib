import pefile
import os

def analyze_pefile(filepath, network_functions):
    pe = pefile.PE(filepath)

    functions = []
    try:
        for x in pe.DIRECTORY_ENTRY_IMPORT:
            for y in x.imports:
                functions.append((y.name).decode('utf-8'))
    except Exception: pass

    matched_functions = list(set(network_functions) & set(functions))

    for match in matched_functions:
        if len(match) != 0:
            print(f'{filepath}: {match}')


dir_to_search = 'C:\\Program Files (x86)\\Internet Explorer'

network_functions = [
    "DeleteIPAddress", "FreeMibTable", "GetAdaptersAddresses", "GetAnycastIpAddressEntry",
    "GetAnycastIpAddressTable", "GetBestRoute2", "GetHostNameW", "GetIpAddrTable",
    "GetIpStatisticsEx", "GetUnicastIpAddressTable", "IcmpCloseHandle", "IcmpCreateFile",
    "IcmpSendEcho", "MultinetGetConnectionPerformance", "MultinetGetConnectionPerformanceW",
    "NetAlertRaise", "NetAlertRaiseEx", "NetApiBufferAllocate", "NetApiBufferFree",
    "NetApiBufferReallocate", "NetApiBufferSize", "NetFreeAadJoinInformation",
    "NetGetAadJoinInformation", "NetAddAlternateComputerName", "NetCreateProvisioningPackage",
    "NetEnumerateComputerNames", "NetGetJoinableOUs", "NetGetJoinInformation",
    "NetJoinDomain", "NetProvisionComputerAccount", "NetRemoveAlternateComputerName",
    "NetRenameMachineInDomain", "NetRequestOfflineDomainJoin", "NetRequestProvisioningPackageInstall",
    "NetSetPrimaryComputerName", "NetUnjoinDomain", "NetValidateName", "NetGetAnyDCName",
    "NetGetDCName", "NetGetDisplayInformationIndex", "NetQueryDisplayInformation",
    "NetGroupAdd", "NetGroupAddUser", "NetGroupDel", "NetGroupDelUser", "NetGroupEnum",
    "NetGroupGetInfo", "NetGroupGetUsers", "NetGroupSetInfo", "NetGroupSetUsers",
    "NetLocalGroupAdd", "NetLocalGroupAddMembers", "NetLocalGroupDel", "NetLocalGroupDelMembers",
    "NetLocalGroupEnum", "NetLocalGroupGetInfo", "NetLocalGroupGetMembers", "NetLocalGroupSetInfo",
    "NetLocalGroupSetMembers", "NetMessageBufferSend", "NetMessageNameAdd", "NetMessageNameDel",
    "NetMessageNameEnum", "NetMessageNameGetInfo", "NetFileClose", "NetFileEnum", "NetFileGetInfo",
    "NetRemoteComputerSupports", "NetRemoteTOD", "NetScheduleJobAdd", "NetScheduleJobDel",
    "NetScheduleJobEnum", "NetScheduleJobGetInfo", "GetNetScheduleAccountInformation",
    "SetNetScheduleAccountInformation", "NetServerDiskEnum", "NetServerEnum", "NetServerGetInfo",
    "NetServerSetInfo", "NetServerComputerNameAdd", "NetServerComputerNameDel",
    "NetServerTransportAdd", "NetServerTransportAddEx", "NetServerTransportDel",
    "NetServerTransportEnum", "NetWkstaTransportEnum", "NetUseAdd", "NetUseDel", "NetUseEnum",
    "NetUseGetInfo", "NetUserAdd", "NetUserChangePassword", "NetUserDel", "NetUserEnum",
    "NetUserGetGroups", "NetUserGetInfo", "NetUserGetLocalGroups", "NetUserSetGroups",
    "NetUserSetInfo", "NetUserModalsGet", "NetUserModalsSet", "NetValidatePasswordPolicyFree",
    "NetValidatePasswordPolicy", "NetWkstaGetInfo", "NetWkstaSetInfo", "NetWkstaUserEnum",
    "NetWkstaUserGetInfo", "NetWkstaUserSetInfo", "NetAccessAdd", "NetAccessCheck",
    "NetAccessDel", "NetAccessEnum", "NetAccessGetInfo", "NetAccessGetUserPerms",
    "NetAccessSetInfo", "NetAuditClear", "NetAuditRead", "NetAuditWrite", "NetConfigGet",
    "NetConfigGetAll", "NetConfigSet", "NetErrorLogClear", "NetErrorLogRead", "NetErrorLogWrite",
    "NetLocalGroupAddMember", "NetLocalGroupDelMember", "NetServiceControl", "NetServiceEnum",
    "NetServiceGetInfo", "NetServiceInstall", "NetWkstaTransportAdd", "NetWkstaTransportDel",
    "NetpwNameValidate", "NetapipBufferAllocate", "NetpwPathType", "NetApiBufferFree",
    "NetApiBufferAllocate", "NetApiBufferReallocate", "WNetAddConnection2", "WNetAddConnection2W",
    "WNetAddConnection3", "WNetAddConnection3W", "WNetCancelConnection", "WNetCancelConnectionW",
    "WNetCancelConnection2", "WNetCancelConnection2W", "WNetCloseEnum", "WNetCloseEnumW",
    "WNetConnectionDialog", "WNetConnectionDialogW", "WNetConnectionDialog1", "WNetConnectionDialog1W",
    "WNetDisconnectDialog", "WNetDisconnectDialogW", "WNetDisconnectDialog1", "WNetDisconnectDialog1W",
    "WNetEnumResource", "WNetEnumResourceW", "WNetGetConnection", "WNetGetConnectionW",
    "WNetGetLastError", "WNetGetLastErrorW", "WNetGetNetworkInformation", "WNetGetNetworkInformationW",
    "WNetGetProviderName", "WNetGetProviderNameW", "WNetGetResourceInformation", "WNetGetResourceInformationW",
    "WNetGetResourceParent", "WNetGetResourceParentW", "WNetGetUniversalName", "WNetGetUniversalNameW",
    "WNetGetUser", "WNetGetUserW", "WNetOpenEnum", "WNetOpenEnumW", "WNetRestoreConnectionW",
    "WNetUseConnection", "WNetUseConnectionW", "RegQueryValueExA"
]

extensions = [".exe", ".dll"]

files_where_to_search = []

for extension in extensions:
    for dir, subdirs, files in os.walk(dir_to_search):
        needed_files = list(map(lambda x: f'{dir}\\{x}', filter(lambda x: x.endswith(extension), files)))
        files_where_to_search.extend(needed_files)

for file in files_where_to_search:
    analyze_pefile(file, network_functions)