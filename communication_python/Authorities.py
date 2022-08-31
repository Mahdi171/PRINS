import sys
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from secretshare import SecretShare
from charm.core.engine.util import bytesToObject, serializeDict,objectToBytes
import random
import time
import zmq
import json
import logging
from PoK import PoK
from TSPS import TSPS
from secretshare import SecretShare as SSS
from Merchant import Merchant
from config import Config

cfg = Config()

context = zmq.Context()
socket_clientSig = context.socket(zmq.REP)
socket_clientSig.bind("tcp://*:"+cfg.client_sig_port) #customer connection
socket_merchant = context.socket(zmq.REP)
socket_merchant.bind("tcp://*:"+cfg.merchant_port) #merchant connection
socket_clientReg = context.socket(zmq.REP)
socket_clientReg.bind("tcp://*:"+cfg.client_reg_port) #customer connection
socket_publish = context.socket(zmq.PUB)
socket_publish.bind("tcp://*:"+cfg.publish_port) #publishing mpk

socket_closeSignal = context.socket(zmq.REP)
socket_closeSignal.bind("tcp://*:"+cfg.close_signal_port)


class Authority():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj
        self.SecretShare = SecretShare(groupObj)
        self.TSPS = TSPS(groupObj)
        self.PoK = PoK(groupObj)
        self.logger = logging.getLogger("A")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler("authority.log")
        fh.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s]: %(message)s'))
        self.logger.addHandler(fh)
        # self.logger.addHandler(logging.StreamHandler())
        self.log("initialized")

    def log(self, m):
        self.logger.debug(m)


    def PGen(self):
        mpk = TSPS.PGen(self)
        return (mpk)


    def AuKeygen(self, mpk, k, n):
        """
        mpk: master public key
        k: authority threshold
        n: number of authorities
        """
        (Sgk_a, Vk_a, Pk_a) = TSPS.kgen(self.TSPS, mpk, k, n)
        return (Sgk_a, Vk_a, Pk_a)


    def MRegister(self, mpk, sgk, vkm, M, k, merchant_index):
        """
        mpk: master public key
        sgk: authority's secret signing key
        vkm: verification key from merchant
        M: number of merchants
        k: authority threshold???
        merchant_index:
        """
        s=group.random()
        mpk['pp'] = mpk['h']**s
        shares= SSS.genShares(self.SecretShare, s, 2, M)
        sigma1 = TSPS.par_sign1(self.TSPS, mpk,vkm,k)
        sigma = TSPS.par_sign2(self.TSPS, sigma1,sgk,k)
        sigmaR = TSPS.reconst(self.TSPS, sigma,k)
        cert_b=sigmaR
        Pk_b=mpk['h']**shares[merchant_index]
        reg_message = (Pk_b,cert_b,mpk)
        return reg_message


    def CuRegister(self, mpk,Sgk_a,Pk_c,C,k):
        sigma1=TSPS.par_sign1(self.TSPS, mpk,Pk_c,k)
        sigma=TSPS.par_sign2(self.TSPS, sigma1,Sgk_a,k)
        sigmaR=TSPS.reconst(self.TSPS, sigma,k)
        cert_c = sigmaR
        return cert_c


    def AuCreate(self,mpk,Sgk_a,kprime,k,wit,w):
        """
        mpk:
        Sgk_a:
        kprime:
        k: authority threshold
        wit: set of witnesses/merchants
        w: number of witnesses to sample
        """
        sigma1 = TSPS.par_sign1(self.TSPS,mpk,kprime,k)
        sigma = TSPS.par_sign2(self.TSPS,sigma1,Sgk_a,k)
        sigmaR = TSPS.reconst(self.TSPS,sigma,k)
        cert_j=sigmaR
        selectedWitnesses = random.sample(wit,w)
        w_j = {}; N_j={}
        list_witness_indexes = []
        for i in range(len(selectedWitnesses)):
            Witness_int=group.hash(objectToBytes(selectedWitnesses[i], group),ZR)
            sigma1 = TSPS.par_sign1(self.TSPS, mpk, mpk['g']**Witness_int,k)
            sigma = TSPS.par_sign2(self.TSPS,sigma1,Sgk_a,k)
            sigmaR = TSPS.reconst(self.TSPS,sigma,k)
            list_witness_indexes.append(wit.index(selectedWitnesses[i]))
            w_j[list_witness_indexes[i]] = sigmaR
            N_j[list_witness_indexes[i]] = mpk['h'] ** Witness_int
        cust_certified_col = (cert_j,w_j,list_witness_indexes, N_j)
        return cust_certified_col


    def main():
        num_mer = cfg.num_merchants
        mers = int(num_mer)
        groupObj = PairingGroup('BN254')
        Auth = Authority(groupObj)
        Mer = []
        for i in range(mers):
            Mer.append('Apple'+str(i+1))
        #setup
        mpk = Auth.PGen()

        # TODO: specify in config
        (sgk_a,vk_a,pk_a) = Auth.AuKeygen(mpk, 5, 10)

        publish_msg = (mpk,pk_a,num_mer)

        publish_msg = objectToBytes(publish_msg,groupObj)
        time.sleep(10)
        # TODO: this part can be improved:
        # need to publish anytime, not only after 10 seconds,
        # this means the customer/merchant need to be listening at this moment
        socket_publish.send(publish_msg)


        while True:
            ready_socks, _, _ = zmq.select([socket_clientReg,socket_clientSig,socket_merchant,socket_closeSignal], [], [])
            for sock in ready_socks:
                if sock == socket_clientReg:
                    message_clientReg = socket_clientReg.recv(zmq.DONTWAIT)
                    message_clientReg = bytesToObject(message_clientReg,groupObj)
                    Auth.log(f"Received registration request from customer with publick key: {message_clientReg}")
                    # TODO do not hardcode 5
                    cert = Auth.CuRegister(mpk,sgk_a, message_clientReg,1,5)
                    Auth.log(f"Sent certificate to customer: {cert}")
                    approved_registration = objectToBytes(cert,groupObj)
                    socket_clientReg.send(approved_registration)

                elif sock == socket_clientSig:
                    #Registration
                    message_client = socket_clientSig.recv(zmq.DONTWAIT)
                    message_client = bytesToObject(message_client,groupObj)
                    k_prime = message_client
                    Auth.log(f"Received request from customer for collateral signature")
                    witness_count = len(cfg.witness_addrs)
                    # TODO: 5 is hard coded
                    data_to_send = Auth.AuCreate(mpk, sgk_a, k_prime, 5, Mer, witness_count)
                    #Auth.log(Col)
                    Auth.log(f"Sent collateral proof: {data_to_send}")
                    collateral_proofs = objectToBytes(data_to_send, groupObj)
                    socket_clientSig.send(collateral_proofs)

                elif sock == socket_merchant:
                    #keygen
                    message_merchant = socket_merchant.recv(zmq.DONTWAIT)
                    message_merchant = bytesToObject(message_merchant,groupObj)
                    Auth.log(f"Received request for public key from merchant")
                    # TODO: 5 is hard coded
                    merchant_registration_data = Auth.MRegister(mpk, sgk_a, message_merchant, mers, 5, 5)
                    merchant_registration_data = objectToBytes(merchant_registration_data,groupObj)
                    socket_merchant.send(merchant_registration_data)
                    Auth.log("Sent public key information to merchant")

                elif sock == socket_closeSignal:
                    Auth.log("Closing")
                    sys.exit(0)

                else:
                    Auth.log("Invalid socket!")
                    sys.exit(1)


if __name__ =="__main__":
    Authority.main()

