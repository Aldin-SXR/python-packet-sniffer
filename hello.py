from flask import Flask, render_template
from random import random
from time import sleep
from threading import Thread, Event
from flask_socketio import SocketIO, emit
import asyncio
from collections import deque
import threading
import sys
import pyshark
import json

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading")

cap = pyshark.LiveCapture(interface='wlp2s0', only_summaries=1, display_filter='ssl')

def format_packet(pkt):
    return {
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

def listen_for_packet(pkt):
    socketio.emit('packet', {'pkt': format_packet(pkt)}, namespace='/test')
    return False

def run():
    cap.sniff_continuously()
    cap.apply_on_packets(listen_for_packet)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect', namespace='/test')
def packets():
    print('Sniffer connected.')
    socketio.start_background_task(target=lambda: run())
    

@socketio.on('filter', namespace='/test')
def filter(filter):
    print('Filter received.')
    cap =  pyshark.LiveCapture(interface='wlp2s0', only_summaries=1, bpf_filter=filter)

if __name__ == '__main__':
    socketio.run(app)