from events_generator import ConsoleEventsGenerator
import logging
from logging.handlers import SysLogHandler, SYSLOG_UDP_PORT
from constants import DeviceType


if __name__ == "__main__":
    eg = ConsoleEventsGenerator(DeviceType.AIE, "127.0.0.1", 514, 10000)
    eg.generate_events()
