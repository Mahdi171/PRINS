import configparser
import collections
import csv


class CSVData:
    def __init__(self):
        self.data = []

    def append(self, data):
        self.data.append(data)

    def save_to(self, fname):
        with open(fname, 'w') as f:
            writer = csv.writer(f, delimiter=',')
            for d in self.data:
                writer.writerow(d)


class Config:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.authority_hostname = config['authority']['hostname']
        self.merchant_hostname  = config['merchant']['hostname']
        self.client_hostname    = config['client']['hostname']

        if int(config['general']['all_local']) != 0:
            self.authority_hostname = "127.0.0.1"
            self.merchant_hostname = "127.0.0.1"
            self.client_hostname = "127.0.0.1"

        self.client_sig_port   = config['authority']['client_sig_port']
        self.client_reg_port   = config['authority']['client_reg_port']
        self.merchant_port     = config['authority']['merchant_port']
        self.publish_port      = config['authority']['publish_port']
        self.close_signal_port = config['authority']['close_signal_port']

        self.client_port = config['client']['port']

        self.witness_ports = []
        self.witness_hostnames = []
        self.witness_dict = collections.OrderedDict()
        i = 0
        while 'witness_batch_'+str(i) in config:
            batch_size = int(config['witness_batch_'+str(i)]['size'])
            hostname = config['witness_batch_'+str(i)]['hostname']

            if int(config['general']['all_local']) != 0:
                hostname = "127.0.0.1"

            starting_port = int(config['witness_batch_'+str(i)]['starting_port'])
            for j in range(batch_size):
                self.witness_hostnames.append(hostname)
                self.witness_ports.append(str(starting_port + j))
            i += 1

            assert (hostname, i) not in self.witness_dict
            self.witness_dict[(hostname, i)] = (starting_port, batch_size)

        self.client_sig_addr = "tcp://" + self.authority_hostname + ":" + self.client_sig_port
        self.client_reg_addr = "tcp://" + self.authority_hostname + ":" + self.client_reg_port
        self.merchant_addr = "tcp://" + self.authority_hostname + ":" + self.merchant_port
        self.publish_addr = "tcp://" + self.authority_hostname + ":" + self.publish_port
        self.close_signal_addr = "tcp://" + self.authority_hostname + ":" + self.close_signal_port

        self.client_addr = "tcp://" + self.client_hostname + ":" + self.client_port
        self.witness_addrs = ["tcp://" + h + ":" + p for h, p in  zip(self.witness_hostnames, self.witness_ports)]

        self.batch_count = int(config['general']['batch_count'])
        self.batch_size = int(config['general']['batch_size'])
        self.num_merchants = int(config['general']['num_merchants'])
        self.dummy_verification_count = int(config['general']['dummy_verification_count'])
        self.use_tsps = bool(int(config['general']['use_tsps']))


if __name__ == "__main__":
    cfg = Config()
    print(cfg.__dict__)
