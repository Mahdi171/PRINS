from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from secretshare import SecretShare
from charm.core.engine.util import serializeDict,objectToBytes, bytesToObject, deserializeDict
from secretshare import SecretShare as SSS
from BLS import BLS01
from PoK import PoK
from TSPS import TSPS
from config import Config, CSVData
import zmq
import math
import logging
import time

cfg = Config()

class Merchant():
    def __init__(self):
        global groupObj
        groupObj = PairingGroup('BN254')
        self.PoK = PoK(groupObj)
        self.SSS = SecretShare(groupObj)
        self.context = zmq.Context()
        self.socket_receiveProof = self.context.socket(zmq.REQ)
        self.TSPS = TSPS(groupObj)
        self.BLS01 = BLS01(groupObj)
        self.logger = logging.getLogger("M")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler("merchant.log")
        fh.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s]: %(message)s'))
        self.logger.addHandler(fh)
        # self.logger.addHandler(logging.StreamHandler())
        self.log("initialized")

    def log(self, m):
        self.logger.debug(m)

    #requesting public parameters from authority
    def request_pp(self):
        self.log("Connecting to authority, requesting parameters")
        socket_pull = self.context.socket(zmq.SUB)
        socket_pull.setsockopt(zmq.SUBSCRIBE, b"")
        socket_pull.connect(cfg.publish_addr)
        msg = socket_pull.recv()
        mpk = bytesToObject(msg, groupObj)
        socket_pull.close()
        return mpk[0],mpk[1],mpk[2]

    def MKeygen(self,mpk,M):
        Vk_b={};Sk_b={}
        for i in range(M):
            (vk_b,sk_b)=BLS01.keygen(self.BLS01, mpk['g'])
            Vk_b[i]=vk_b; Sk_b[i]=sk_b
        return (Vk_b,Sk_b)

    #Requesting public key from authority
    def request_pk(self, merchant_index, vk_b):
        vk_merchant = vk_b[merchant_index]
        vk_merchant = objectToBytes(vk_merchant,groupObj)
        self.log("Connecting to authority, requesting public key")
        socket = self.context.socket(zmq.REQ)
        socket.connect(cfg.merchant_addr)
        self.log("Sending request for public key")
        socket.send(vk_merchant)

        message_pk = socket.recv()
        merchant_public_key = bytesToObject(message_pk, groupObj)
        pk_merchant = merchant_public_key[0]
        cert_merchant = merchant_public_key[1]
        new_mpk = merchant_public_key[2]
        self.log(f"Received public key [ {pk_merchant} ]")
        socket.close()
        return pk_merchant, cert_merchant, new_mpk


    #Requesting payment guarantee from Customer
    def request_proof(self, merchant_public_key, new_mpk):
        self.log("Requesting proofs and ciphertext from customer")
        proof_request_cust = (merchant_public_key,new_mpk)
        merchant_public_key = objectToBytes(proof_request_cust, groupObj)
        self.socket_receiveProof.send(merchant_public_key)
        #time.sleep(0.2)
        received_proof =  self.socket_receiveProof.recv()
        self.log("Received payment guarantee from customer")
        received_proof = bytesToObject(received_proof, groupObj)
        return received_proof


    def witness_send(self, for_witness, sockets):
        for_witness = objectToBytes(for_witness, groupObj)
        for sock in sockets:
            # sock.send(for_witness, flags=zmq.NOBLOCK)
            sock.send(for_witness)
        self.log("witness sent")


    # process responses from witnesses
    def witness_recv(self, sockets, witnessindexes):
        ok = False
        from_witness = []
        while True:
            ready_socks, _, _ = zmq.select(sockets, [], [], timeout=10)
            for s in ready_socks:
                msg = s.recv()
                msg = bytesToObject(msg, groupObj)
                from_witness.append(msg)

            if len(from_witness) >= math.ceil(len(witnessindexes)/2):
                self.log("Verification succeeded")
                ok = True
                break

        for sock in sockets:
            sock.close()

        self.log("witness sockets closed")

        return ok


    #Verifying payment guarantee from customer and appending payment ciphertext to the ledger
    def Verification(self, mpk, Pk_a, N, pi ,inp, R, htime,L1,L2,pk,wprime_j,witnessindexes,N_j,Sk_w,socket_witnesses,Ledger):
        if TSPS.verify(self.TSPS, mpk, Pk_a, N, inp['cert'])==1 and \
                mpk['e_gh'] * (R ** (-htime))==pi['pi2']['y'] and \
                    L1 * (inp['C']**(-htime)) == pi['pi4']['y'] and \
                    L2 * (inp['C1'] ** (-htime)) == pi['pi3']['y'] and \
                        PoK.verifier3(self.PoK,mpk['g'],pi['pi1']['y'],pi['pi1']['z'],pi['pi1']['t'],mpk['pp']) == 0 and \
                        PoK.verifier5(self.PoK,pi['pi2']['y'],pi['pi2']['z'],pi['pi2']['t'],R) == 1 and \
                            PoK.verifier4(self.PoK,pi['pi3']['y'],pi['pi3']['z'],pi['pi3']['t'],inp['C1'],pk) == 1 and \
                                PoK.verifier2(self.PoK,inp['C'],mpk['e_gh'],pi['pi4']['y'],pi['pi4']['z1'],pi['pi4']['z2'],pi['pi4']['t'],inp['u'])==1:
                                        return True
        else:
            return False


    # revealing identity of customer in case of double-spending
    def Decryption(self, mpk, ct1, M1, ct2, M2):
        Coeff = SSS.recoverCoefficients([groupObj.init(ZR, M1+1),groupObj.init(ZR, M2+1)])
        return ct2['C'] / ((ct1['C1']**Coeff[M1+1])*(ct2['C1']**Coeff[M2+1]))

    def close_authority(self):
        sock = self.context.socket(zmq.REQ)
        sock.connect(cfg.close_signal_addr)
        sock.send(b"close")

    def spend_and_verify(m, num_mer, mer_pk, mer_cert, new_mpk, sk_b, pk_a):

        request_time_start = time.time()
        spend_proofs, N, list_witness_index, N_j, htime = m.request_proof(mer_pk,new_mpk)
        request_time = time.time() - request_time_start

        sending_time_start = time.time()
        sk_w = {}
        Ledger=dict.fromkeys(list_witness_index, [])
        m.log(f"ledger: {Ledger}")
        #counter = 0
        for j in list_witness_index:
            sk_w[j] = sk_b[j]
            #counter += 1

        L1=pair(new_mpk['g'],new_mpk['pp'])
        L2=pair(new_mpk['g'],mer_pk)

        # prepare messages
        pis = [p[0] for p in spend_proofs]
        inps = [p[1] for p in spend_proofs]
        Rs = [p[2] for p in spend_proofs]
        wprime_js = [p[3] for p in spend_proofs]

        # prepare messages for witness
        for_witness_msgs = [(new_mpk, pk_a, R, wprime_j, list_witness_index, N_j, sk_w, Ledger) for R, wprime_j in zip(Rs, wprime_js)]

        # send the messages to witnesses
        # TODO reuse these connections? but remember not to close them after receiving messages from witness
        verification_time_start = time.time()
        socket_witnesses = []
        for host in cfg.witness_addrs:
            sock = m.context.socket(zmq.REQ)
            m.log(f"Connecting to witness {host}")
            sock.connect(host)
            socket_witnesses.append(sock)

        m.witness_send(for_witness_msgs, socket_witnesses)
        sending_time = time.time() - sending_time_start

        # do local verification while waiting for witnesses
        local_verification_time_start = time.time()
        for pi, inp, R, wprime_j in zip(pis, inps, Rs, wprime_js):
            ok = m.Verification(new_mpk, pk_a,N, pi, inp, R, htime, L1, L2, mer_pk,wprime_j, list_witness_index, N_j, sk_w, socket_witnesses, Ledger)
            if not ok:
                sys.exit("verification failed!")
        local_verification_time = time.time() - local_verification_time_start

        # get responses from witnesses
        ok = m.witness_recv(socket_witnesses, list_witness_index)
        if not ok:
            sys.exit("verification failed!")
        verification_time = time.time() - verification_time_start

        result=[num_mer]
        result.append(request_time)
        result.append(sending_time)
        result.append(local_verification_time)
        result.append(verification_time)
        result.append(len(wprime_js[0]))

        return result


    def main():
        m = Merchant()
        mpk,pk_a,num_mer = m.request_pp()

        Mer = []
        for i in range(int(num_mer)):
            Mer.append('Apple'+str(i+1))
        (vk_b,sk_b) = m.MKeygen(mpk,int(num_mer))
        mer_pk, mer_cert, new_mpk = m.request_pk(5, vk_b) # TODO do not hardcode 5

        # connect to the client
        m.log(f"Connecting to customer on {cfg.client_addr}")
        m.socket_receiveProof.connect(cfg.client_addr)

        data = CSVData()
        title = ['total_merchants', 'request time', 'sending time', 'local verification time', 'verification time', 'total_witnesses']
        data.append(title)

        for batch_id in range(cfg.batch_count):
            result = Merchant.spend_and_verify(m, num_mer, mer_pk, mer_cert, new_mpk, sk_b, pk_a)
            data.append(result)

        data.save_to(f"merchant_{cfg.batch_size}.csv")
        # m.close_authority()
        print("Done")


if __name__ == "__main__":
    Merchant.main()


