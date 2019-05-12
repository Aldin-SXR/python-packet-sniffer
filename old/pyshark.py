import pyshark;

capture = pyshark.LiveCapture(interface='wlp2s0')
capture.set_debug();

capture.sniff(timeout=5);