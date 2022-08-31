import zmq
import sys

port = "5530"
if len(sys.argv) > 1:
    port =  sys.argv[1]
    int(port)

context = zmq.Context()
socket = context.socket(zmq.REP)
print("listening on port", port)
socket.bind(f"tcp://*:{port}")

while True:
    print("waiting")
    message = socket.recv()
    print("received:", message)
    socket.send(message)

