# Python Packet Sniffer
A simple packet sniffer written in Python, with the ability to utilize Wireshark dissectors (display filters.)

Built with Flask, PyShark and AngularJS.

## Installation & Running
The project has to be run in a Linux environment with Python 3.7+.

1. Go (`cd`) to the project directory.
2. `python3 -m venv sniffer`
3. `. sniffer/bin/activate`
4. `pip install -r requirements.txt`
5. Start the app by running `sudo python3 app.py` (has to be run as superuser due to socket permissions.)

