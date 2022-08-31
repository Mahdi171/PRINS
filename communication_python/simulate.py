# This file is the "orchestrator" as well as the client.
# It will setup the authority, merchant and witness and then send transactions.
# The number of transaction and the rate that they are sent can be customized.

from fabric import Connection
import time
from Customer_preprocessed import Customer
from config import Config
import sys

cfg = Config()
TIMEOUT = 10000

PROJECT_DIR = "communication_python"
CMD_PREFIX = f"cd {PROJECT_DIR}/ && python3 "

def make_conns():
    auth_conn = Connection(cfg.authority_hostname)
    merc_conn = Connection(cfg.merchant_hostname)
    witn_conns = {(url, i): Connection(url) for url, i in cfg.witness_dict.keys()}

    msg = "Connected to {0.connection.host} with hostname {0.stdout}"

    print(msg.format(auth_conn.run("hostname")))
    print(msg.format(merc_conn.run("hostname")))

    for conn in witn_conns.values():
        print(msg.format(conn.run("hostname")))

    return (auth_conn, merc_conn, witn_conns)


def killall(auth_conn, merc_conn, witn_conns):
    for conn in list(witn_conns.values())+[auth_conn, merc_conn]:
        conn.run("pkill -f Authorities.py", warn=True)
        conn.run("pkill -f Merchant_witness_distributed.py", warn=True)
        conn.run("pkill -f Witness.py", warn=True)


def killauth(auth_conn):
    auth_conn.run("pkill -f Authorities.py", warn=True)


def copy_ini(conn):
    conn.put("config.ini", remote=PROJECT_DIR)

def simulate(auth_conn, merc_conn, witn_conns):

    print("Starting witnesses")
    ctr = 0
    for k, conn in witn_conns.items():
        _, batch_size = cfg.witness_dict[k]
        for _ in range(batch_size):
            print("witness", ctr)
            conn.run(f"{CMD_PREFIX}Witness.py {ctr}", disown=True, echo=True, timeout=TIMEOUT)
            ctr += 1

            # NOTE: for some reason fabric crashes when running too many commands; so we reset it
            if ctr % 10 == 0:
                conn.close()
                conn.open()


    time.sleep(2)

    print("Starting authority")
    auth_promise = auth_conn.run(CMD_PREFIX + 'Authorities.py 2> authority_err.log', disown=True, timeout=TIMEOUT)

    print("Starting merchant")
    merc_promise = merc_conn.run(CMD_PREFIX + 'Merchant_witness_distributed.py 2> merchant_err.log', asynchronous=True, echo=True, timeout=TIMEOUT)

    print("Starting customer")
    Customer.main()

    print("merc output:")
    merc_msgs = merc_promise.join()
    print(merc_msgs.stdout)
    print(merc_msgs.stderr)
    merc_conn.close()

    for conn in witn_conns.values():
        conn.close()

    # print("auth output:")
    # print(auth_promise.join())


if __name__ == "__main__":
    auth_conn, merc_conn, witn_conns = make_conns()
    killall(auth_conn, merc_conn, witn_conns)
    simulate(auth_conn, merc_conn, witn_conns)


