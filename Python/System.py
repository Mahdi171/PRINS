from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
#from charm.toolbox.ABEnc import Input, Output
from secretshare import SecretShare
from charm.core.engine.util import serializeDict,objectToBytes
import random
from datetime import datetime
from openpyxl import load_workbook
from openpyxl import Workbook
from PoK import PoK
from SPTS import SPTS
from BLS import BLS01
from secretshare import SecretShare as SSS
from Witness import Witness
import math

class Nirvana():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj
        self.SecretShare = SecretShare(groupObj)
        self.SPTS = SPTS(groupObj)
        self.BLS01 = BLS01(groupObj)
        self.PoK = PoK(groupObj)
        self.witness = Witness(groupObj)

    def PGen(self):
        mpk = SPTS.PGen(self)
        return (mpk)

    def AuKeygen(self, mpk,k,n):
        (Sgk_a,Vk_a,Pk_a) = SPTS.kgen(self,mpk,k,n)
        return (Sgk_a,Vk_a,Pk_a)

    def MKeygen(self,mpk,M):
        Vk_b={};Sk_b={}
        for i in range(M):
            (vk_b,sk_b)=BLS01.keygen(self.BLS01, mpk['g'])
            Vk_b[i]=vk_b; Sk_b[i]=sk_b    
        return (Vk_b,Sk_b)
    
    def MRegister(self,mpk,sgk,vkm,M,k):
        Pk_b={}
        s=group.random()
        mpk['pp'] = mpk['h']**s
        shares= SSS.genShares(self.SecretShare, s, 2, M)
        for i in range(1,M):
            Pk_b[i]=mpk['h']**shares[i]
        return (Pk_b)

    def CuKeyGen(self,mpk,C):
        Sk_c={}; Pk_c={}; M_c={}
        for i in range(C):
            sk=group.random(); Sk_c[i]=sk
            pk=mpk['g'] ** sk; Pk_c[i]=pk
            M_c[i]=SPTS.iDH(self.SPTS,mpk,Pk_c[i],sk)
        return (Sk_c,Pk_c,M_c)

    def CuRegister(self, mpk,Sgk_a,Pk_c,M_c,C,k):
        cert_c={}
        for i in range(C):
            sigma=SPTS.par_sign(self.SPTS,mpk,Sgk_a,M_c[i],k)
            sigmaR=SPTS.reconst(self.SPTS, sigma,k)
            cert_c[i]=sigmaR
        return cert_c

    def CuCreate(self, mpk,M_c,cert_cn):
        key = group.random()
        kprime = mpk['g']**key
        M_j=SPTS.iDH(self.SPTS,mpk,kprime,key)
        pi=PoK.prover1(self.PoK,mpk['g'],kprime,key)
        certprime = SPTS.Randomize(self.SPTS,mpk,M_c ,cert_cn)
        return (key, M_j, kprime, certprime,pi)
    
    def AuCreate(self,mpk,Sgk_a,kprime,k,M_j,certprime,picol):
        sigma = SPTS.par_sign(self.SPTS,mpk,Sgk_a,M_j,k)
        cert_j = SPTS.reconst(self.SPTS,sigma,k)
        return cert_j

    def Spending(self, mpk, key, pk_bm, time,ID,Sk_cn,cert_j,M_j):
        r = mpk['g'] ** (1/(key+time))
        R = pair(r,mpk['h'])
        A1 = (pair(r, mpk['pp']))
        C = ID * A1
        C1 = pair(r, pk_bm)
        Mprime_j, certprime_j = SPTS.Randomize(self.SPTS,mpk,M_j,cert_j)
        y2 = R ** key; A= A1 ** key
        u = mpk['e_gh'] ** (key * Sk_cn)
        (proof1) = PoK.prover3(self.PoK,mpk['g'],A,key,mpk['pp']) #Proof of SPS
        (proof2) = PoK.prover4(self.PoK,y2,key,R) # Proof of Aggeragetd collatorals
        (proof3) = PoK.prover3(self.PoK,r,C1**key,key,pk_bm) #Proof of ciphertext C1
        (proof4) = PoK.prover2(self.PoK,C,mpk['e_gh'],((C/ID)**key)*(mpk['e_gh']**(-time*Sk_cn)),key,(-time*Sk_cn)) #Proof of ciphertext C0
        inp = { 'C': C, 'C1': C1 , 'Mprime_j':Mprime_j, 'cert': certprime_j, 'u':u}
        pi = {'pi1': proof1,'pi2': proof2,'pi3': proof3,'pi4': proof4}
        return (pi, inp, R)


    def Verification(self, mpk, Pk_a, M_j, pi ,inp, R, Ledger, time,L1,L2,pk,Sk_b,m,Vk_b):
        if R not in Ledger and \
            SPTS.verify(self.SPTS, mpk, Pk_a, inp['Mprime_j'], inp['cert'])==1 and \
                mpk['e_gh'] * (R ** (-time))==pi['pi2']['y'] and \
                    L1 * (inp['C']**(-time)) == pi['pi4']['y'] and \
                    L2 * (inp['C1'] ** (-time)) == pi['pi3']['y'] and \
                        PoK.verifier3(self.PoK,mpk['g'],pi['pi1']['y'],pi['pi1']['z'],pi['pi1']['t'],mpk['pp']) == 0  and \
                        PoK.verifier5(self.PoK,pi['pi2']['y'],pi['pi2']['z'],pi['pi2']['t'],R) == 1 and \
                            PoK.verifier4(self.PoK,pi['pi3']['y'],pi['pi3']['z'],pi['pi3']['t'],inp['C1'],pk) == 1 and \
                                PoK.verifier2(self.PoK,inp['C'],mpk['e_gh'],pi['pi4']['y'],pi['pi4']['z1'],pi['pi4']['z2'],pi['pi4']['t'],inp['u'])==1:
                                sigma=Witness.WitnessApproval(self.witness,mpk, pk, R, Sk_b,Ledger,m)
                                sigmaAg=BLS01.aggregate(self.BLS01,sigma)
                                vkAg=1
                                print(len(sigma))
                                for i in range(m):
                                    vkAg*=Vk_b[i]
                                if len(sigma)>m and BLS01.verify(self.BLS01,vkAg,sigmaAg,R)==0:
                                    print("Verification succeeded")
        else:
            print("Verification failed")

    def Decryption(self, mpk, ct1, M1, ct2, M2): 
        Coeff = SSS.recoverCoefficients([group.init(ZR, M1+1),group.init(ZR, M2+1)])
        return ct2['C'] / ((ct1['C1']**Coeff[M1+1])*(ct2['C1']**Coeff[M2+1]))

