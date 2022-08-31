from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import Input, Output
from secretshare import SecretShare
from charm.core.engine.util import serializeDict,objectToBytes, bytesToObject
import random
import time
import zmq
import logging
from datetime import datetime
from PoK import PoK
from TSPS import TSPS
from BLS import BLS01
from secretshare import SecretShare as SSS
from config import Config, CSVData

cfg = Config()

class Customer():

    def __init__(self):
        global groupObj
        groupObj = PairingGroup('BN254')
        self.PoK = PoK(groupObj)
        self.SSS = SecretShare(groupObj)
        self.TSPS = TSPS(groupObj)
        self.BLS01 = BLS01(groupObj)
        self.PoK = PoK(groupObj)
        self.context = zmq.Context()
        self.logger = logging.getLogger("C")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler("customer.log")
        fh.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s]: %(message)s'))
        self.logger.addHandler(fh)
        self.logger.addHandler(logging.StreamHandler())
        self.log("initialized")
        # self.witness = Witness(groupObj)

    def log(self, m):
        self.logger.debug(m)

    #Requesting public parameters
    def request_pp(self):
        self.log("Connecting to authority, requesting parameters")
        socket_pull = self.context.socket(zmq.SUB)
        socket_pull.setsockopt(zmq.SUBSCRIBE, b"")
        socket_pull.connect(cfg.publish_addr)
        msg = socket_pull.recv()
        mpk = bytesToObject(msg, groupObj)
        socket_pull.close()
        return mpk[0],mpk[1],mpk[2]

    def CuKeyGen(self,mpk):
        sk=groupObj.random()
        pk=mpk['g'] ** sk
        return (sk,pk)

    #requesting registration certificate from authority
    def request_cert(self,pk):
        pk = objectToBytes(pk,groupObj)
        self.log("Connecting to authorities, requesting registration certificate")
        socket = self.context.socket(zmq.REQ)
        socket.connect(cfg.client_reg_addr)
        socket.send(pk)

        reg_certificate = socket.recv()
        reg_certificate = bytesToObject(reg_certificate, groupObj)
        socket.close()

        return reg_certificate

    #requesting collateral proof from authority
    def CuCreate(self, mpk,cert_cn):
        K={}; Kprime={}; Col={}
        K = groupObj.random()
        Kprime = mpk['g']**K
        N = mpk['h']**K
        pi=PoK.prover1(self.PoK,mpk['g'],Kprime,K)
        certprime = TSPS.Randomize(self.TSPS, cert_cn)
        #return (K, N, Kprime, certprime,pi)
        customer_Col_proof = (Kprime)
        self.log("Connecting to authority, requesting collateral certification")
        socket = self.context.socket(zmq.REQ)
        socket.connect(cfg.client_sig_addr)
        self.log("Sending certification request...")
        customer_Col_proof = objectToBytes(customer_Col_proof,groupObj)
        socket.send(customer_Col_proof)
        message_colla = socket.recv()
        message_colla = bytesToObject(message_colla, groupObj)
        self.log(f"Received certified collateral [ {message_colla} ]")
        socket.close()

        return (message_colla,pi,certprime,N,K,Kprime)

    #Generating the payment guarantee for requesting merchant.
    def Spending(self, mpk, key, pk_bm, htime,ID,Sk_cn,cert_j,w_j,listWitness):
        r = mpk['g'] ** (1/(key+htime))
        R = pair(r,mpk['h'])
        A1 = (pair(r, mpk['pp']))
        C = ID * A1
        C1 = pair(r, pk_bm)
        wprime_j = {}
        if cfg.use_tsps:
            for i in listWitness:
                wprime_j[i] = TSPS.Randomize(self.TSPS,w_j[str(i)])
        certprime_j = TSPS.Randomize(self.TSPS,cert_j)
        y2 = R ** key; A= A1 ** key
        u = mpk['e_gh'] ** (key * Sk_cn)
        (proof1) = PoK.prover3(self.PoK,mpk['g'],A,key,mpk['pp']) #Proof of SPS
        (proof2) = PoK.prover4(self.PoK,y2,key,R) # Proof of Aggeragetd collatorals
        (proof3) = PoK.prover3(self.PoK,r,C1**key,key,pk_bm) #Proof of ciphertext C1
        (proof4) = PoK.prover2(self.PoK,C,mpk['e_gh'],((C/ID)**key)*(mpk['e_gh']**(-htime*Sk_cn)),key,(-htime*Sk_cn)) #Proof of ciphertext C0
        inp = { 'C': C, 'C1': C1 , 'cert': certprime_j, 'u':u}
        pi = {'pi1': proof1,'pi2': proof2,'pi3': proof3,'pi4': proof4}
        return (pi, inp, R, wprime_j)


    def spend(c, num_mer, socket_receiveProofReq, sk_c, key, certified_col, N):


        waiting_time_start = time.time()
        c.log(f"Waiting for proof request")
        merchant_col_req = socket_receiveProofReq.recv()
        merchant_col_req = bytesToObject(merchant_col_req, groupObj)
        pk_merchant = merchant_col_req[0]
        new_mpk = merchant_col_req[1]
        c.log(f"Received proof request from merchant: {pk_merchant}")
        htime=groupObj.hash(objectToBytes(str(datetime.now()), groupObj),ZR)
        ID = new_mpk['e_gh'] ** sk_c
        waiting_time = time.time() - waiting_time_start

        spend_time_start= time.time()
        spend_proof = [c.Spending(new_mpk,key,pk_merchant,htime,ID,sk_c,certified_col[0],certified_col[1],certified_col[2]) for _ in range(cfg.batch_size)]

        message_to_mer = (spend_proof, N, certified_col[2], certified_col[3], htime)
        spend_proof = objectToBytes(message_to_mer, groupObj)
        socket_receiveProofReq.send(spend_proof)
        c.log("Sent payment guarantee to merchant")
        spend_time = time.time() - spend_time_start

        result = [num_mer]
        result.append(waiting_time)
        result.append(spend_time)
        return result


    def main():
        c = Customer()
        mpk,pk_a,num_mer = c.request_pp()
        (sk_c,pk_c) = c.CuKeyGen(mpk)
        (reg_certificate) = c.request_cert(pk_c)
        (certified_col,pi,certprime,N,key,kprime) = c.CuCreate(mpk,reg_certificate)
        socket_receiveProofReq = c.context.socket(zmq.REP)
        socket_receiveProofReq.bind("tcp://*:"+cfg.client_port)

        data=CSVData()
        title = ['total_merchants','waiting time','spending Time']
        data.append(title)

        for batch_id in range(cfg.batch_count):
            c.log(f"spending batch {batch_id}, each batch has {cfg.batch_size} transactions")
            result = Customer.spend(c, num_mer, socket_receiveProofReq, sk_c, key, certified_col, N)
            data.append(result)

        data.save_to(f"customer_{cfg.batch_size}.csv")


if __name__ == "__main__":
    Customer.main()


