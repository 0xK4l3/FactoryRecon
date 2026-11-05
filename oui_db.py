"""
OUI (Organizationally Unique Identifier) database and MAC vendor lookup.
Includes a curated high-coverage table of common IT, networking, embedded, and
industrial automation manufacturers (PLCs, HMIs, cameras, routers, PCs, etc.).
"""

OUI_DATABASE: dict[str, str] = {
    # Industrial Automation & PLCs (Siemens, Rockwell/Allen-Bradley, Schneider, Omron, Beckhoff, Wago, Phoenix, Mitsubishi, Festo)
    "00:0E:8C": "Siemens AG (Industrial Automation)",
    "00:1B:1B": "Siemens AG",
    "00:1C:06": "Siemens Numerical Control",
    "00:1F:F8": "Siemens AG (SIMATIC)",
    "28:63:36": "Siemens AG",
    "68:05:CA": "Siemens AG",
    "DC:4A:3E": "Siemens AG",
    "E0:DC:A0": "Siemens AG",
    "00:00:BC": "Rockwell Automation (Allen-Bradley)",
    "00:1D:9C": "Rockwell Automation (Allen-Bradley)",
    "5C:88:16": "Rockwell Automation (Allen-Bradley)",
    "E4:90:69": "Rockwell Automation (Allen-Bradley)",
    "F4:54:33": "Rockwell Automation (Allen-Bradley)",
    "00:00:54": "Schneider Electric (Modicon/Telemecanique)",
    "00:80:F4": "Schneider Electric (Modicon)",
    "00:80:67": "Schneider Electric",
    "20:89:84": "Schneider Electric",
    "00:01:05": "Beckhoff Automation",
    "00:30:DE": "WAGO Kontakttechnik",
    "00:A0:45": "Phoenix Contact",
    "00:21:62": "Phoenix Contact",
    "64:69:BC": "Phoenix Contact",
    "00:00:0A": "Omron Corporation",
    "00:30:05": "Fujitsu / Omron",
    "00:40:66": "Mitsubishi Electric",
    "D8:47:10": "Mitsubishi Electric",
    "00:0E:F0": "Festo AG & Co. KG",
    "00:09:91": "GE Fanuc Automation",
    "00:50:4E": "B&R Industrial Automation",
    "00:60:65": "B&R Industrial Automation",
    "00:02:A2": "Hilscher Gesellschaft fuer Systemautomation",
    "00:03:1D": "Weintek Labs (HMI)",
    "00:1E:9A": "Moxa Technologies",
    "00:90:E8": "Moxa Technologies",
    "00:0C:E7": "Advantech Co.",
    "00:D0:C9": "Advantech Co.",
    "74:FE:48": "Advantech Co.",
    "00:07:AF": "Red Lion Controls",
    "00:01:36": "Turck (Hans Turck GmbH)",
    "00:0D:81": "Pepperl+Fuchs",
    "00:06:71": "Sick AG (Sensors)",
    "00:13:95": "Keyence Corporation",
    "00:01:FC": "Keyence Corporation",
    "00:02:D9": "ifm electronic",
    "00:1A:A0": "ABB Automation",
    "00:21:99": "ABB Oy",
    "00:24:59": "ABB Automation Products",
    "00:03:23": "Cognex Corporation (Vision Systems)",
    "00:D0:24": "Cognex Corporation",
    "00:0B:DB": "Yaskawa Electric",
    "00:20:B5": "Yaskawa Electric",
    "00:E0:64": "Fanuc Robotics",
    "00:90:C2": "KUKA Roboter GmbH",
    "00:03:37": "HMS Industrial Networks (Anybus/Ewon)",
    "00:30:11": "HMS Industrial Networks",

    # IP Cameras & Security (Hikvision, Dahua, Axis, Hanwha, Bosch)
    "00:40:8C": "Axis Communications (IP Camera)",
    "AC:CC:8E": "Axis Communications (IP Camera)",
    "B8:A4:4F": "Axis Communications (IP Camera)",
    "28:57:BE": "Hikvision Digital Technology",
    "44:19:B6": "Hikvision Digital Technology",
    "54:C4:15": "Hikvision Digital Technology",
    "BC:AD:28": "Hikvision Digital Technology",
    "C0:56:E3": "Hikvision Digital Technology",
    "3C:EF:8C": "Dahua Technology",
    "4C:11:BF": "Dahua Technology",
    "90:02:A9": "Dahua Technology",
    "A0:BD:1D": "Dahua Technology",
    "00:09:18": "Samsung Techwin / Hanwha Vision",
    "00:07:5F": "Bosch Security Systems",

    # Embedded / Single Board Computers (Raspberry Pi, Espressif, Arduino, BeagleBone)
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "D8:3A:DD": "Raspberry Pi Trading",
    "2C:CF:67": "Raspberry Pi Trading",
    "24:0A:C4": "Espressif Inc. (ESP32/ESP8266)",
    "30:AE:A4": "Espressif Inc. (ESP32/ESP8266)",
    "84:CC:A8": "Espressif Inc. (ESP32/ESP8266)",
    "A4:CF:12": "Espressif Inc. (ESP32/ESP8266)",
    "A8:48:FA": "Arduino AG",
    "04:A3:16": "Microchip Technology",
    "00:04:A3": "Microchip Technology",
    "D8:80:39": "Microchip Technology",
    "00:80:E1": "STMicroelectronics",
    "00:04:9F": "NXP Semiconductors / Freescale",

    # Networking & Routers (Cisco, Ubiquiti, MikroTik, TP-Link, Netgear, Aruba, Fortinet)
    "00:00:0C": "Cisco Systems",
    "00:1B:54": "Cisco Systems",
    "00:25:45": "Cisco Systems",
    "F0:4A:02": "Cisco Systems",
    "04:18:D6": "Ubiquiti Inc.",
    "24:5A:4C": "Ubiquiti Inc.",
    "74:83:C2": "Ubiquiti Inc.",
    "80:2A:A8": "Ubiquiti Inc.",
    "F0:9F:C2": "Ubiquiti Inc.",
    "00:0C:42": "MikroTik RouterBOARD",
    "18:FD:74": "MikroTik RouterBOARD",
    "4C:5E:0C": "MikroTik RouterBOARD",
    "64:D1:54": "MikroTik RouterBOARD",
    "C4:AD:34": "MikroTik RouterBOARD",
    "DC:2C:6E": "MikroTik RouterBOARD",
    "E4:8D:8C": "MikroTik RouterBOARD",
    "14:CC:20": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation",
    "84:16:F9": "TP-Link Corporation",
    "B0:95:75": "TP-Link Corporation",
    "B8:66:85": "Sagemcom / ISP Gateway",
    "20:E5:2A": "NETGEAR",
    "A0:40:A0": "NETGEAR",
    "00:0B:86": "Aruba Networks (HPE)",
    "00:09:0F": "Fortinet Inc.",

    # PCs, Servers, Virtual Machines & NICs (Intel, Realtek, Dell, HP, Lenovo, Apple, VMware, VirtualBox, Hyper-V)
    "00:E0:4C": "Realtek Semiconductor",
    "18:C0:4D": "Gigabyte Technology (Realtek NIC)",
    "74:56:3C": "GIGA-BYTE TECHNOLOGY",
    "D8:BB:C1": "Micro-Star INT'L (MSI)",
    "04:D4:C4": "ASUSTek COMPUTER",
    "2C:FD:A1": "ASUSTek COMPUTER",
    "00:1B:21": "Intel Corporate",
    "3C:FD:FE": "Intel Corporate",
    "68:05:CA": "Intel Corporate",
    "A0:36:9F": "Intel Corporate",
    "00:14:22": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "F8:B1:56": "Dell Inc.",
    "00:17:A4": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard",
    "94:57:A5": "Hewlett Packard",
    "00:21:CC": "Lenovo",
    "50:7B:9D": "Lenovo",
    "00:50:56": "VMware, Inc. (Virtual Machine)",
    "00:0C:29": "VMware, Inc. (Virtual Machine)",
    "08:00:27": "Oracle VirtualBox (Virtual NIC)",
    "0A:00:27": "Oracle VirtualBox (Host-Only Adapter)",
    "00:15:5D": "Microsoft Hyper-V (Virtual NIC)",
    "00:1C:42": "Parallels, Inc.",
    "3C:22:FB": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",

    # Printers & Office Equipment (Zebra, Brother, Epson, HP, Canon)
    "00:07:4D": "Zebra Technologies (Industrial Printer)",
    "AC:3F:A4": "Zebra Technologies (Industrial Printer)",
    "00:80:77": "Brother Industries",
    "30:05:5C": "Brother Industries",
    "00:26:AB": "Seiko Epson Corporation",
    "00:00:85": "Canon Inc.",
    "00:11:32": "Synology Incorporated (NAS)",
    "24:5E:BE": "QNAP Systems (NAS)",
}


def lookup_mac_vendor(mac: str) -> str:
    """
    Returns the manufacturer name for a given MAC address.
    Supports formats like 'AA:BB:CC:DD:EE:FF' or 'AA-BB-CC-DD-EE-FF'.
    """
    if not mac or len(mac) < 8:
        return "Desconocido"
    clean = mac.upper().replace("-", ":").strip()
    prefix = clean[:8]
    if prefix in OUI_DATABASE:
        return OUI_DATABASE[prefix]

    # Check locally administered bit (second hex digit of first byte is 2, 6, A, or E)
    try:
        first_byte = int(clean[:2], 16)
        if first_byte & 0x02:
            return "MAC Local / Virtual / Aleatoria"
    except ValueError:
        pass

    return "Fabricante Desconocido"

