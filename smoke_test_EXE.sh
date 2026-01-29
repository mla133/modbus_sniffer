#!/bin/bash 
 pyinstaller modbus-sniffer.spec -y --clean

 echo -n "Tests using PCAP replay\n"
 ./dist/modbus-sniffer.exe watch --pcap "tests/pcaps/sample.pcapng" --watch 100 200 205
 ./dist/modbus-sniffer.exe watch --pcap "tests/pcaps/sample.pcapng" --fc 3 --watch 100 --deltas-only
 ./dist/modbus-sniffer.exe watch --pcap "tests/pcaps/sample.pcapng" --fc 3 --trigger-change-reg 100 --include-regs 200 205 --payload-format json

 echo -n "Tests using 'Ethernet 4' interface\n"
 ./dist/modbus-sniffer.exe watch --iface "Ethernet 4" --watch 100 200 205
 ./dist/modbus-sniffer.exe watch --iface "Ethernet 4" --fc 3 --watch 100 --deltas-only
 ./dist/modbus-sniffer.exe watch --iface "Ethernet 4" --fc 3 --trigger-change-reg 100 --include-regs 200 205 --payload-format json
