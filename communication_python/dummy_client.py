import zmq
import sys

addr = "18.138.226.122:5530"
if len(sys.argv) > 1:
    addr = sys.argv[1]

ctx = zmq.Context()
sock = ctx.socket(zmq.REQ)
sock.connect("tcp://"+addr)
for i in range(10):
    sock.send_string(f"ping {i}")
    print("sent to", addr)
    msg = sock.recv()
    print("received", msg)

