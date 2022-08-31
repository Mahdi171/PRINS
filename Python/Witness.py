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
from TSPS import TSPS
from BLS import BLS01
from secretshare import SecretShare as SSS


class Witness():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj
        self.TSPS = TSPS(groupObj)
        self.BLS01 = BLS01(groupObj)
        

    def WitnessApproval(self,mpk, pk, R, Sk_b,Ledger,m):
        sigma = {}
        for i in range(m):
            if R not in Ledger[i]:
                sigma[i] = BLS01.sign(self.BLS01,Sk_b[i], R)
                #Ledger[i].append(R)
        return sigma

