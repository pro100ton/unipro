from enum import IntEnum

# Endpoint events templates
ENDPOINT_TEMPLATE_1 = 'CEF:0|InfoWatch ARMA|ARMAIE|2.3.4|white_list|White list|6|rt=1639592220  act=DENIED cat=not whitelisted fname=Firefox Setup 95.0.msi filePath=\\\\Device\\\\HarddiskVolume4\\\\Firefox Setup 95.0.msi\n'
ENDPOINT_TEMPLATE_2 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|integrity_control|Integrity control|5|rt=1613559558000 act=CREATE  fname=test.bat  filePath=C:\\temp\\test.bat '
ENDPOINT_TEMPLATE_3 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|integrity_control|Integrity control|5|rt=1613559555000 act=WRITE fname=Hello — копия (2).txt filePath=C:\\temp\\file.exe'
ENDPOINT_TEMPLATE_4 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|integrity_control|Integrity control|5|rt=1613559581000 act=REMOVE fname=Hello — копия (2).txt filePath=C:\\temp\\Hello — копия (2).txt'
ENDPOINT_TEMPLATE_5 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|integrity_control|Integrity control|5|rt=1639592258 act=RENAME fname=C:\temp\Hello.txt filePath=C:\\temp\\Goodbye.txt'
ENDPOINT_TEMPLATE_6 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|integrity_control|Integrity control|5|rt=1604793739000 act=MOVE fname=13245 — копия (3).txt filePath=C:\\temp\\Test_dir\\13245 — копия (3).txt'
ENDPOINT_TEMPLATE_7 = 'CEF:0|InfoWatch ARMA|ARMAIE|2.3.4|white_list|White list|6|rt=1639592258  act=DENIED cat=not whitelisted fname=vc_runtimeAdditional_x86.msi filePath=\\\\Device\\\\HarddiskVolume4\\\\ProgramData\\\\Package Cache\\\\{572DCD10-CF2E-43D1-8151-8BD9AC9086D0}v14.28.29913\\\\packages\\\\vcRuntimeAdditional_x86\\\\vc_runtimeAdditional_x86.msi\n'
ENDPOINT_TEMPLATE_8 = 'CEF:0|InfoWatch ARMA|ARMAIE|2.3.4|usb|USB|6|rt=1639592452 act=DENIED cs1Label=pid cs1=1000 cs2Label=vid cs2=8564 cs3Label=serial_number cs3=JKPQMZ1G msg=class:8 subclass:6;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0\n'
ENDPOINT_TEMPLATE_9 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|usb|USB|5|rt=1604793739000 act=DENIED cs1Label=pid cs1=1000 cs1Labe2=vid cs2=90c cs3Label=serial_number cs3=0376119070023321 msg=[class:c1 subclass:s1;class:s2 subclass:s2]'
ENDPOINT_TEMPLATE_10 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|usb|USB|5|rt=1604793739000 act=ALLOWED ccs1Label=pid cs1=1000 cs1Labe2=vid cs2=90c cs3Label=serial_number cs3=0376119070023852 msg=[class:8 subclass:6]'
ENDPOINT_TEMPLATE_11 = 'CEF:0|InfoWatch ARMA|ARMAIE|2.3.4|usb|USB|6|rt=1639592541 act=DENIED cs1Label=pid cs1=810 cs2Label=vid cs2=45e cs3Label=serial_number cs3=Љ msg=class:239 subclass:2;class:14 subclass:1;class:14 subclass:2;class:1 subclass:1;class:1 subclass:2;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0;class:0 subclass:0\n'
ENDPOINT_TEMPLATE_12 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1613559551000 act=scan_start fname=file_1.exe filePath=C:\\temp\\file_1.exe'
ENDPOINT_TEMPLATE_13 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1604793739000 act=scan_stop fname=file_2.exe filePath=C:\\dir_2\\file_2.exe'
ENDPOINT_TEMPLATE_14 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1605610654000 act=remove_scan_tasc fname=file_3.exe filePath=C:\\dir_2\\file_2.exe'
ENDPOINT_TEMPLATE_15 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1604793739000 act=find_virus fname=file_bad.exe filePath=C:\\Documents\\file_bad.exe  cs1Label=virus_name cs1=drakula'
ENDPOINT_TEMPLATE_16 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1639485222000 act=file_deleted fname=file_2.bat filePath=C:\\windows\\file_2.bat'
ENDPOINT_TEMPLATE_17 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1604793739000 act=scan_error fname=file_3.exe filePath=C:\\windows\\file_3.exe  cs1Label=errfor_name cs1=File not found'
ENDPOINT_TEMPLATE_18 = 'CEF:0|InfoWatch ARMA|ARMAIE|3.5.2_7|antivirus|Antivirus|5|rt=1639592258 act=scan_failed fname=file_4.bat filePath=C:\\system32\\file_4.bat cs1Label=errfor_name cs1=Scan error'
AIE_EVENTS = {
    'white_list': [
        ENDPOINT_TEMPLATE_1,
        ENDPOINT_TEMPLATE_7
    ],
    'ic': [
        ENDPOINT_TEMPLATE_2,
        ENDPOINT_TEMPLATE_3,
        ENDPOINT_TEMPLATE_4,
        ENDPOINT_TEMPLATE_5,
        ENDPOINT_TEMPLATE_6
    ],
    'usb': [
        ENDPOINT_TEMPLATE_8,
        ENDPOINT_TEMPLATE_9,
        ENDPOINT_TEMPLATE_10,
        ENDPOINT_TEMPLATE_11
    ],
    'av': [
        ENDPOINT_TEMPLATE_12,
        ENDPOINT_TEMPLATE_13,
        ENDPOINT_TEMPLATE_14,
        ENDPOINT_TEMPLATE_15,
        ENDPOINT_TEMPLATE_16,
        ENDPOINT_TEMPLATE_17,
        ENDPOINT_TEMPLATE_18
    ]
}

class DeviceType(IntEnum):
    ALL = 0
    AIF = 1
    AMC = 2
    AIE = 3
    AIS = 4
    RANDOM_CEF = 5