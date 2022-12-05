from abc import ABC, abstractmethod
from constants import DeviceType, AIE_EVENTS
import logging
from logging.handlers import SysLogHandler, SYSLOG_UDP_PORT

# Following constants created to prepare mock logs
FIREWALL_LOG_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|8|cs1=63 cs2=deviceInboundInterface=lo0 act=разрешение (pass) src=127.0.0.1 deviceDirection=in proto=icmp dst=127.0.0.1 spt=46084 dpt=53 rt=1604793739000 log_from=filterlog cid=None\n'
FIREWALL_LOG2_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|5|cs1=61 cs2=deviceInboundInterface=igb0 act=block deviceDirection=in proto=icmp src=127.0.0.1 dst=127.0.0.2 rt=1604793739000 deviceFacility=vfilterlog cid=None\n'
FIREWALL_LOG3_TEMPLATE3 = '<1>CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=80 cs2=deviceInboundInterface=lo0 act=pass deviceDirection=in class=0x00 flowlabel=0x00000 src=127.0.0.1 dst=127.0.0.2 hlim=1 proto=udp payload-length=76 rt=1604793739000 deviceFacility=filterlog cid=None __line=Oct 27 17:14:09 arma.localdomain filterlog: 80,,,0,lo0,match,pass,in,6,0x00,0x00000,1,udp,17,76,fe80::20c:29ff:fe69:de4d,ff02::1:2,546,547,76'
FIREWALL_LOG4_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=73 deviceInboundInterface=em0 act=pass deviceDirection=0 proto=tcp seq=273959436 rt=1611148012000 deviceFacility=filterlog src=192.168.56.1 dst=192.168.56.104 spt=53738 dpt=80 cs1Label=RuleNumber'
SURICATA_LOG_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|5|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728 cs1Label=Signature cs2=12 cs2Label=line_number rev=1 classification=null priority=3 proto=TCP ip_src=10.20.30.50 port_src=80 ip_dst=10.20.30.1 port_dst=34568 act=start'
SURICATA_LOG_SEVERITY = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|8|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728 cs1Label=Signature cs2=12 cs2Label=line_number rev=1 classification=null priority=3 proto=TCP ip_src=10.20.30.50 port_src=80 ip_dst=10.20.30.1 port_dst=34568 act=start'
SURICATA_LOG_MMS = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|5|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728 cs1Label=Signature cs2=12 cs2Label=line_number rev=1 priority=3 proto=TCP ip_src=10.20.30.50 port_src=80 ip_dst=10.20.30.1 port_dst=34568 act=start'
NTP_LOG_TEMPLATE = "CEF:0|InfoWatch ARMA|ARMAIF|3.5|ntppower|Ntp power|4|rt=1611238449000 deviceFacility=ntpd dvcpid=61184 cs1=4.2.8p14@1.3728-o msg=Starting cs1Label=ntpd version act=start"
NTP_LOG2_TEMPLATE = "CEF:0|InfoWatch ARMA|ARMAIF|3.8.0-dev.19|ntpmanualsync|NTP manual sync|3|rt=1664869933000 deviceFacility=ntp msg=Successfully synced time after 1 attempts cs1=1 cs1Label=attemptsCount"
WEB_LOGIN_LOG_TEMPLATE = "CEF:0|InfoWatch ARMA|ARMAIF|3.5|webauth|Web authentication|0|rt=1604793739000 log_from=armaif cid=None url=/index.php msg=Successful login suser=root src=10.20.30.1 outcome=failure reason=no_idea\n"
WEB_LOGIN_LOG2_TEMPLATE = "CEF:0|InfoWatch ARMA|ARMAIF|3.5|webauth|Web authentication|0|rt=1604793739000 log_from=armaif cid=None url=/index.php msg=Successful login suser=root src=192.168.2.106 __line=Feb 21 11:31:37 arma armaif: /index.php: Successful login for user 'root' from: 192.168.2.106 outcome=success"
WEB_LOGIN_LOG3_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|webauth|Web authentication|0|rt=1611148011000 deviceFacility=armaif request=/index.php msg=Successful login suser=root src=192.168.56.1 outcome=success'
WEB_LOGIN_LOG4_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|webauth|Web authentication|0|rt=1611148011000 deviceFacility=armaif request=/index.php msg=Successful login suser=root src=192.168.56.1 outcome=success'
WEB_ACCESS_LOG_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|lighttpdaccess|Lighttpd Access|5|rt=1604793739000 deviceFacility=lighttpd dvcpid=29727 src=10.20.30.1 dst=10.20.30.50 requestMethod=GET url_relative=/api/core/menu/search/?_\\=1569482291550 app=HTTP/1.1 cs1=200 cs2=65734 cs1Label=responseCode cs2Label=bodyLength request=http://10.20.30.50/ui/netsnmp/general/index requestClientApplication=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0 mechanic=Lighttpd" \n'
WEB_ACCESS_LOG2_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|lighttpdaccess|Lighttpd Access|5|rt=1604793739000 deviceFacility=lighttpd dvcpid=79894 src=192.168.2.106 dst=192.168.2.1 requestMethod=GET request=/widgets/api/get.php?load\=system%2Cgateway%2Cinterfaces&_\=1582284700985 app=HTTP/1.1 cs1=200 cs2=2425 cs1Label=responseCode cs2Label=bodyLength requestContext=http://192.168.2.1/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0 __line=Feb 21 11:34:33 arma lighttpd[79894]: 192.168.2.106 192.168.2.1 - [21/Feb/2020:11:34:33 +0000] "GET /widgets/api/get.php?load\=system%2Cgateway%2Cinterfaces&_\=1582284700985 HTTP/1.1" 200 2425 "http://192.168.2.1/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0"'
WEB_ACCESS_LOG3_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|lighttpdaccess|Lighttpd Access|8|rt=1604793739000 deviceFacility=lighttpd dvcpid=79894 src=192.168.2.106 dst=192.168.2.1 requestMethod=GET request=/widgets/api/get.php?load\=system%2Cgateway%2Cinterfaces&_\=1582284700985 app=HTTP/1.1 cs1=200 cs2=2425 cs1Label=responseCode cs2Label=bodyLength requestContext=http://192.168.2.1/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0 __line=Feb 21 11:34:33 arma lighttpd[79894]: 192.168.2.106 192.168.2.1 - [21/Feb/2020:11:34:33 +0000] "GET /widgets/api/get.php?load\=system%2Cgateway%2Cinterfaces&_\=1582284700985 HTTP/1.1" 200 2425 "http://192.168.2.1/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0"'
WEB_ACCESS_LOG4_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|lighttpdaccess|Lighttpd Access|5|rt=1605610654000 deviceFacility=lighttpd dvcpid=44121 src=10.20.30.1 dst=10.20.30.54 requestMethod=GET request=/api/core/menu/search/?_\=1574012278012 app=HTTP/1.1 cs1=302 cs2=66085 requestContext=http://10.20.30.54/ui/captiveportal requestClientApplication=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0 cs1Label=responseCode cs2Label=bodyLength'
WEB_ACCESS_LOG5_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6-rc2|accessalert|Acess alert|1|rt=1620805384000 deviceFacility=lighttpd dvcpid=94479 src=192.168.1.201 dst=192.168.1.101 requestMethod=GET request=/ui/arpwatcher/general app=HTTP/1.1 cs1=200 cs2=118524 requestContext=https://192.168.1.101/ui/arpwatcher/index requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 cs1Label=responseCode cs2Label=bodyLength'
ARPWATCH_LOG_TEMPLATE = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|arpwatchalert|Arpwatch alert|6|rt=1604793739000 deviceFacility=arpwatch cid=None message=new station src=10.0.3.2 src_old=None mac_src=52:54:0:12:35:2 mac_src_old=None mechanic=Arpwatch act=Destroy_all_humanity __line=Jan 30 08:41:33 arma arpwatch: new station 10.0.3.2 52:54:0:12:35:2#012 description=Было выявлено несанкционированное подключение устройства IP: 10.0.3.2, MAC: 52:54:0:12:35:2\n'
ARPWATCH_LOG_TEMPLATE2 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|arpwatchalert|Arpwatch alert|5|rt=1604793739000 deviceFacility=arpwatch cid=None message=new station src=192.168.1.100 src_old=None mac_src=0:c:29:e6:74:14 mac_src_old=None mechanic=Arpwatch __line=May 15 14:08:36 arma arpwatch: new station 192.168.1.100 0:c:29:e6:74:14 description=Было выявлено несанкционированное подключение устройства IP: 192.168.1.100, MAC: 0:c:29:e6:74:14\n'
ARPWATCH_LOG_TEMPLATE3 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|arpwatchalert|Arpwatch alert|5|rt=1604793739000 deviceFacility=arpwatch cid=None message=new station src=192.168.1.100 src_old=None act=Destroy_all_humanity mac_src=0:c:29:e6:74:14 mac_src_old=None mechanic=Arpwatch __line=May 15 14:08:36 arma arpwatch: new station 192.168.1.100 0:c:29:e6:74:14 description=Было выявлено несанкционированное подключение устройства IP: 192.168.1.100, MAC: 0:c:29:e6:74:14\n'
ARPWATCH_LOG_TEMPLATE4 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6-rc2|arpwatchalert|Arpwatch alert|7|rt=1620805293000 deviceFacility=arpwatch act=new station src=192.168.1.101 smac=00:50:56:bd:86:c5 cs1Label=src_old cs2Label=smac_old'

# These logs are for networkmap
ARPWATCH_CONNECT_LOG_1 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=192.168.1.20 smac=0a:00:27:00:00:00  cs1Label=src_old cs2Label=smac_old'
ARPWATCH_CONNECT_LOG_2 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=192.168.1.21 smac=0a:00:28:00:00:00 cs1Label=src_old cs2Label=smac_old'
ARPWATCH_CONNECT_LOG_3 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=10.10.1.11 smac=0a:00:29:00:00:00 cs1Label=src_old cs2Label=smac_old'
ARPWATCH_CONNECT_LOG_4 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=10.10.1.21 smac=0a:00:30:00:00:00 cs1Label=src_old cs2Label=smac_old'
ARPWATCH_CONNECT_LOG_5 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=17.234.12.34 smac=0a:00:31:00:00:00 cs1Label=src_old cs2Label=smac_old'
SURICATA_CONNECT_LOG_1 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|5|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728  cs1Label=Signature cs2=12 cs2Label=line_number msg=Test message 1  rev=1 priority=3 proto=TCP ip_src=192.168.1.20 port_src=80 ip_dst=192.168.1.21 port_dst=34568 act=start\n'
SURICATA_CONNECT_LOG_2 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|5|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728 cs1Label=Signature cs2=12 cs2Label=line_number rev=1 msg=Test message 2 priority=3 proto=TCP ip_src=17.234.12.34 port_src=80 ip_dst=192.168.1.21 port_dst=34568 act=start\n'
SURICATA_CONNECT_LOG_3 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.0|idspower|IDS power|5|rt=1604793739000 log_from=suricata deviceFacility=28775 gid=1 cs1=429496728 cs1Label=Signature cs2=12 cs2Label=line_number rev=1 msg=Test message 3 priority=3 proto=TCP ip_src=192.168.1.21 port_src=80 ip_dst=10.10.1.11 port_dst=34568 act=start\n'
SURICATA_CONNECT_LOG_4 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6|idsalert|IDS alert|5|rt=1604793739000 deviceFacility=suricata dvcpid=7814 cs1=1 act=429496728 cs2=1 msg=ARMA_S7Comm_PLC_Stop proto=TCP src=192.168.1.1 spt=49238 dst=192.168.2.2 dpt=102 cs1Label=gid cs2Label=rev'
SURICATA_CONNECT_LOG_5 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idsalert|IDS Alert|5|rt=1639485803000 deviceFacility=suricata dvcpid=81078 cs1=1 act=2002752 cs2=4 msg=ET POLICY Reserved Internal IP Traffic proto=UDP src=192.168.244.1 spt=68 dst=192.168.244.254 dpt=67 cs1Label=gid cs2Label=rev'
SURICATA_CONNECT_LOG_6 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idspower|IDS power|3|rt=1639485268000 deviceFacility=suricata msg=Test message 5 dvcpid=36147 act=shutdown'
SURICATA_CONNECT_LOG_7 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idsalert|IDS rule alert|5|rt=1639485222000 deviceFacility=suricata dvcpid=36147 msg=Suricate message cs1=alert modbus any any -> any any (msg:\"SURICATA Modbus invalid Length\"; app-layer-event:modbus.invalid_length; classtype:protocol-command-decode; sid:2250003; rev:2;) filePath=/usr/local/etc/suricata/opnsense.rules/modbus-events.rules cs2=6 reason=parse signature error cs1Label=signature cs2Label=lineNumber'
SURICATA_CONNECT_LOG_8 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idsalert|IDS Alert|5|rt=1639471522000 deviceFacility=suricata dvcpid=51009 cs1=1 act=2210056 cs2=1 msg=SURICATA STREAM bad window update proto=TCP src=192.168.0.1 spt=51784 dst=192.168.0.3 dpt=51033 cs1Label=gid cs2Label=rev'
SURICATA_CONNECT_LOG_9 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idsalert|IDS Alert|5|rt=1639485548000 deviceFacility=suricata dvcpid=81078 cs1=1 act=2002752 cs2=4 msg=ET POLICY Reserved Internal IP Traffic proto=TCP src=192.168.0.204 spt=443 dst=192.168.0.23 dpt=52659 cs1Label=gid cs2Label=rev'
SURICATA_CONNECT_LOG_10 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|idsalert|IDS rule alert|5|rt=1639470621000 deviceFacility=suricata dvcpid=51009 msg=Suricata message 3 cs1=alert http any any -> any any (msg:\"Black list checksum match and extract SHA256\"; filesha256:fileextraction-chksum.list; filestore; sid:30; rev:1;) filePath=/usr/local/etc/suricata/opnsense.rules/files.rules cs2=52 reason=parse signature error cs1Label=signature cs2Label=lineNumber'
SURICATA_CONNECT_LOG_11 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6-rc12|idsalert|IDS rule alert|5|rt=1634546072000 deviceFacility=suricata dvcpid=77565 msg=Suricata message 6 cs1=alert modbus any any -> any any (msg:"SURICATA Modbus invalid Unit Identifier"; app-layer-event:modbus.invalid_unit_identifier; classtype:protocol-command-decode; sid:2250004; rev:2;) filePath=/usr/local/etc/suricata/opnsense.rules/modbus-events.rules cs2=8 reason=parse signature error cs1Label=signature cs2Label=lineNumber'
SURICATA_CONNECT_LOG_12 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6-rc.55|integrityalert|Integrity alert|0|rt=1647277200000 msg=Test message 5 outcome=success deviceFacility=integrity'

FIREWALL_CONNECT_LOG_1 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=73 deviceInboundInterface=em0 act=pass deviceDirection=0 proto=tcp seq=273959436 rt=1611148012000 deviceFacility=filterlog src=192.168.1.21 dst=10.10.1.21 spt=53738 dpt=80 cs1Label=RuleNumber'
FIREWALL_CONNECT_LOG_2 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=73 deviceInboundInterface=em0 act=pass deviceDirection=0 proto=tcp seq=273959436 rt=1611148012000 deviceFacility=filterlog src=10.10.1.11 dst=10.10.1.21 spt=53738 dpt=80 cs1Label=RuleNumber'
FIREWALL_CONNECT_LOG_3 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=73 deviceInboundInterface=em0 act=pass deviceDirection=0 proto=tcp seq=273959436 rt=1611148012000 deviceFacility=filterlog src=192.168.1.20 dst=10.10.1.11 spt=53738 dpt=80 cs1Label=RuleNumber'
FIREWALL_CONNECT_LOG_4 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5|pfalert|PF rule alert|0|cs1=73 deviceInboundInterface=em0 act=pass deviceDirection=0 proto=tcp seq=273959436 rt=1611148012000 deviceFacility=filterlog src=1.1.1.1 dst=2.2.2.2 spt=53738 dpt=80 cs1Label=RuleNumber'
FIREWALL_CONNECT_LOG_5 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.6.rc.36|pfalert|PF rule alert|0|cs1=79 deviceInboundInterface=le0 act=pass deviceDirection=1 proto=udp rt=1639065415000 deviceFacility=filterlog src=192.168.157.132 dst=192.168.157.2 spt=58642 dpt=53 cs1Label=RuleNumber'
ARPWATCH_CONNECT_LOG_6 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=1.1.1.1 smac=0a:00:27:00:00:00 cs1Label=src_old cs2Label=smac_old'
ARPWATCH_CONNECT_LOG_7 = 'CEF:0|InfoWatch ARMA|ARMAIF|3.5.2_7|arpwatchalert|Arpwatch alert|5|rt=1613559551000 deviceFacility=arpwatch act=new station src=2.2.2.2 smac=0a:00:27:00:00:00 cs1Label=src_old cs2Label=smac_old'

FIREWALL_PF_LOG = '<134>Mar  2 09:57:56 arma.localdomain filterlog: CEF:0|InfoWatch ARMA|ARMAIF|3.6-rc.55|pfalert|PF rule alert|0|cs1=63 deviceInboundInterface=vmx1 act=pass deviceDirection=1 class=0x00 flowlabel=0x00000 hlim=1 proto=udp payload-length=76 rt=1646215076000 deviceFacility=filterlog src=fe80::250:56ff:febd:4716 dst=ff02::1:2 spt=546 dpt=547 cs1Label=RuleNumber'


class AbstractEventGenerator(ABC):
    """Abastract class for events generator"""

    @abstractmethod
    def generate_events(self, query_string: str) -> str:
        """Abstract metod for generating events for target host depending on 
        query_string parameter

        Args:
            query_string (str): query string for specializing type of events 
            which user wants to send
        """
        pass


class ConsoleEventsGenerator(AbstractEventGenerator):
    def __init__(self, 
                 device_type: int, 
                 host: str, 
                 port: int, 
                 amount_of_events: int) -> None:
        """Initializer for events generators

        Args:
            device_type (int): _description_
            host (str): _description_
            port (int): _description_
            amount_of_events (int): _description_
        """
        self._device_type = device_type
        self._host = host
        self._port = port
        self._amount_of_events = amount_of_events

    def _prepare_aie_events(self) -> list[str]:
        """Forming list of template events, that will be send to AMC

        Returns:
            list[str]: List of template events, whic will be send to AMC
        """
        # TODO: Add precise AIE generator settings
        selected_events = []
        selected_events.extend(AIE_EVENTS['av'])
        selected_events.extend(AIE_EVENTS['ic'])
        selected_events.extend(AIE_EVENTS['usb'])
        selected_events.extend(AIE_EVENTS['white_list'])
        return selected_events

    def _create_logger(self) -> any:
        """Private function for prepearing logger class to send logs

        Returns:
            any: logger handlers for sending logs
        """
        # TODO: find how to annotate types from external libs
        logger = logging.getLogger('cef_syslog_export')
        logger.setLevel(logging.INFO)
        syslog_handler = SysLogHandler(address=(self._host, self._port))
        syslog_handler.setLevel(logging.DEBUG)

        fmt = logging.Formatter(f'%(message)s')
        syslog_handler.setFormatter(fmt)
        logger.addHandler(syslog_handler)
        return logger, syslog_handler

    def generate_events(self) -> str:
        """Main function for generating events

        Args:
            query_string (str): query string should be passed in following 
            format:
                {
                    "device_type": number from device_enum (int)
                    "host": host ip address (str)
                    "port": host port (int)
                    "amount_of_events": amount of events to send (int)
                }
        """

        # First - AIE logs are only available
        # TODO: Add support for rest device types
        if self._device_type != DeviceType.AIE:
            return {"status": "error", "message": "Unsupported device type"}

        # Create list of logs to send
        logs_to_send = []

        # Form final list of logs for sending
        if self._device_type == DeviceType.AIE:
            logs_to_send.extend(self._prepare_aie_events())


        # Sending logs to destination
        logger, handler = self._create_logger()
        counter = 0
        for i in range(self._amount_of_events):
            for log in logs_to_send:
                logger.info(log)
                counter+=1
        #TODO: replace with bot logger
        print(counter)
        logger.removeHandler(handler)

