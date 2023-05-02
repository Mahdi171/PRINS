### Hi there 👋

# Private Double-Spending Protection for Low Latency Payments on Blockchains

Our system enables a customer to instantly transact with a merchant using a cryptocurrency of their choice. [Link](https://eprint.iacr.org/2023/583) to the research paper accepted to ACISP'23.

The structure of this repository is as follows:

* `Python`: Python code to emulate the payment system locally. Please execute Test.py for testing.

	- BLS.py: Python code to emulate BLS signatures
	- System.py: Python code to emulate payments in a local environment
	- PoK.py: Python code for NIZKs
	- TSPS.py: Python code to emulate our proposed TSPS scheme
	- Test.py: Python code to test System.py locally
	- secretshare.py: Python code for Shamir secret sharing
 
* `communication_python`: Python code to emulate our payment system in a distributed environment. 

	- BLS.py: Python code to emulate BLS signatures
	- Customer_preprocessed.py: Python code to emulate a customer in our payment system
	- Merchant_witness_distributed.py: Python code to emulate a merchant with distributed witnesses
	- Authorities.py: Python code to emulate authorities
	- TSPS.py: Python code to emulate our proposed TSPS scheme
	- Witness.py: Python code to emulate a witness located at a separate locations
	- secretshare.py: Python code for Shamir secret sharing
    - simulate.py: Please execute `python3 simulate.py` to simulate our payment system
    - config.ini: The configuration for setting hostnames and ports for the simulation, see the file for documentation

* `contracts`: The smart contract for our payment system
    
	- AuthorityContract: A smart contract for accepting customer deposits, payments and remunerating victim merchants


## Install

### Dependencies

The main requirements are charm-crypto, zmq and fabric.
See `requirements.txt` for all the details.
Do not use pip to install `requirements.txt` since charm-crypto needs to installed manually.

### Using virtual-env

If you want charm-crypto to be in a virtual environment,
here's what you should do.
- Create a virtual environment with `python3 -m venv cons-env`.
- Install [pbc](https://crypto.stanford.edu/pbc/download.html) to the virtual-env,
i.e., you need to set the prefix: `./configure --prefix=/home/myname/cons-env`
- Clone charm-crypto from https://github.com/JHUISI/charm.git.
Do not use the releases, they do not work. Install from the repo.
- Install charm-crypto to the virtual environment, e.g.,
```
./configure.sh --prefix=/home/myname/tmp/cons-env  --extra-ldflags="-L/home/myname/cons-env/lib -L/home/myname/cons-env/lib64
make
make install
```

Make sure to set the extra `LDFLAGS` so that charm-crypto finds pbc as shown above.
- Note that python 3.8 and above seems to be broken for charm-crypto, see [this issue](https://github.com/JHUISI/charm/issues/239).
- It is possible to use `pyenv` to get a different python version.

## Simulation

It is possible to simulate our payment network on multiple machines, this is tested on AWS.
- Copy the source code to all the machine and configure `config.ini` appropriately.
- Setting `all_local=1` will everything to run locally,
if a distributed execution is needed, make sure `all_local=0`.
- Make sure all machines can run `python3 simulate.py` locally, which may involve installing dependencies.
- Pick a machine to act as the customer, it must have non-interactive ssh access to all other machines.
If you're using public key authentication, you can do this with `ssh-add ~/.ssh/machine.pem` but remember to start the ssh agent with `eval $(ssh-agent -s)`.
- Login to the customer machine and execute `python3 simulate.py`.
