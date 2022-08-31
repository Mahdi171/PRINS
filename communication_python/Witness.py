from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.core.engine.util import bytesToObject, serializeDict,objectToBytes
import random
from TSPS import TSPS
from BLS import BLS01
from config import Config, CSVData
import zmq
import sys
import logging
import time

cfg = Config()

class Witness():
    def __init__(self, groupObj, i):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj
        self.TSPS = TSPS(groupObj)
        self.BLS01 = BLS01(groupObj)
        self.i = int(i)
        self.logger = logging.getLogger(f"W-{i}")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(f"witness_{i}.log")
        fh.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s]: %(message)s'))
        self.logger.addHandler(fh)
        # self.logger.addHandler(logging.StreamHandler())
        self.log(f"initialized")

    def log(self, m):
        self.logger.debug(m)

    def WitnessApproval(self):
        context = zmq.Context()
        socket_verify = context.socket(zmq.REP)
        self.log(f"binding to port {cfg.witness_ports[self.i]}")
        socket_verify.bind("tcp://*:"+cfg.witness_ports[self.i])

        waiting_time = []
        working_time = []
        sigmas = []
        for batch_id in range(cfg.batch_count):

            waiting_time_start = time.time()
            self.log(f"waiting")
            received_guarantees = socket_verify.recv() # blocks
            received_guarantees = bytesToObject(received_guarantees, group)
            self.log(f"got a batch of {len(received_guarantees)} guarantees")
            waiting_time.append(time.time() - waiting_time_start)

            working_time_start = time.time()
            ok = True
            for received_guarantee in received_guarantees:
                mpk = received_guarantee[0]
                pk = received_guarantee[1]
                R = received_guarantee[2]
                wprime_j = received_guarantee[3]
                witnessindexes = received_guarantee[4]
                N_j = received_guarantee[5]
                Sk_b = received_guarantee[6]
                Ledger = received_guarantee[7]

                witness_idx = witnessindexes[self.i]
                if R not in Ledger[str(witness_idx)] and \
                    ((not cfg.use_tsps) or (TSPS.verify(self.TSPS,mpk,pk,N_j[str(witness_idx)],wprime_j[str(witness_idx)])==1)):
                    sigma = BLS01.sign(self.BLS01,Sk_b[str(witness_idx)], R)
                    Ledger[str(witness_idx)].append(R)
                    sigmas.append(sigma)
                else:
                    ok = False

                for _ in range(cfg.dummy_verification_count):
                    Ledger[str(witness_idx)]
                    if cfg.use_tsps:
                        TSPS.verify(self.TSPS,mpk,pk,N_j[str(witness_idx)],wprime_j[str(witness_idx)])
                    BLS01.sign(self.BLS01,Sk_b[str(witness_idx)], R)

            if ok:
                self.log(f"Verification succeeded for batch {batch_id}")
                socket_verify.send(objectToBytes(sigmas, group))
            else:
                self.log(f"Verification failed for batch {batch_id}")
            working_time.append(time.time() - working_time_start)

        socket_verify.close()

        return waiting_time, working_time


    def main(i):
        groupObj = PairingGroup('BN254')
        w = Witness(groupObj, i)
        waiting_time, working_time = w.WitnessApproval()

        data = CSVData()
        title = ['waiting time', 'working time']
        data.append(title)
        for a, b in zip(waiting_time, working_time):
            data.append([a, b])

        data.save_to(f"witness_{cfg.batch_size}_{i}.csv")
        print("Done")


if __name__ == "__main__":
    Witness.main(sys.argv[1])
