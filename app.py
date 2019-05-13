from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from time import sleep
import pyshark
import json
from threading import Lock

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading")
NAMESPACE = '/sniffer'

last_filter = ''

# Initial capture - all packets
cap = [
    pyshark.LiveCapture(interface='wlp2s0', only_summaries=1, display_filter=last_filter),
    None
    # pyshark.LiveCapture(interface='wlp2s0')
]

# Set up a worker and a worker threa
worker = None
worker_thread = None

class Worker(object):
    def __init__(self, socketio, cap):
        self.socketio = socketio
        self.cap = cap;
        self.active = False;

    def run(self):
        self.active = True
        # Single sniffer (no port data)
        for packet in self.cap[0].sniff_continuously():
            if self.active is True:
                self.socketio.emit('packet', {'pkt': self.format_packet(packet, None)}, namespace=NAMESPACE)
                sleep(0.1)
            else:
                return

        # Dobule sniffer (extra data)
        # for summary, full in zip(self.cap[0], self.cap[1]):
        #     if self.active is True:
        #         self.socketio.emit('packet', {'pkt': self.format_packet(summary, full)}, namespace=NAMESPACE)
        #     else:
        #         return

    def start(self):
        self.active = True

    def stop(self):
        self.active = False
    
    def set_capture(self, cap):
        self.cap = cap

    def format_packet(self, pkt, pkt2):
        packet = {
            # "delta": pkt.delta,
            "no": pkt.no,
            "source": pkt.source,
            "destination": pkt.destination,
            "info": pkt.info,
            "length": pkt.length,
            "protocol": pkt.protocol,
            "summary_line": pkt.summary_line,
            "time": pkt.time
        }
        # Check for transport layer ports
        if hasattr(pkt2, 'udp'):
            packet["src_port"] = pkt2.udp.srcport
            packet["dst_port"] = pkt2.udp.dstport
        elif hasattr(pkt2, 'tcp'):
            packet["src_port"] = pkt2.tcp.srcport
            packet["dst_port"] = pkt2.tcp.dstport
        return packet

# Routes and socket events
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect', namespace=NAMESPACE)
def sniff():
    print('Sniffer connected.')
    global worker
    global worker_thread
    if worker is not None and worker_thread is not None:
        worker.stop()
        worker_thread.join()
    worker = Worker(socketio, cap)
    # worker_thread = socketio.start_background_task(target=worker.run)
    socketio.emit('successful connection', namespace=NAMESPACE)

@socketio.on('stop', namespace=NAMESPACE)
def stop():
    print('Sniffer stopped.')
    global worker
    worker.stop()

@socketio.on('start', namespace=NAMESPACE)
def stop():
    print('Sniffer started.')
    global worker
    global worker_thread
    if worker_thread is not None:
        worker_thread.join()
    worker.start()
    worker_thread = socketio.start_background_task(target=worker.run)

@socketio.on('filter', namespace=NAMESPACE)
def filter(df):
    print('Filter received: ' + df)
    last_filter = df
    # Edit 'all' filter to be '' (all packets)
    if df == 'all':
        df = ''
    # Stop the existing worker thread
    global worker
    global worker_thread
    worker.stop()
    print('Worker stopped.')
    cap = [
        pyshark.LiveCapture(interface='wlp2s0', only_summaries=1, display_filter=df),
        None
        # pyshark.LiveCapture(interface='wlp2s0', display_filter=df)
    ]
    # Restart the worker thread with new data
    if worker_thread is not None:
        worker_thread.join(5)
        print('Thread joined.')
    worker.cap = cap;
    worker_thread = socketio.start_background_task(target=worker.run)
    print('New thread started.')
    # Notify filter change
    socketio.emit('filter changed', namespace=NAMESPACE);


@socketio.on('disconnect', namespace=NAMESPACE)
def sniff():
    print('Sniffer disconnected.')
    global worker
    worker.stop()

if __name__ == '__main__':
    socketio.run(app)