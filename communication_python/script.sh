#!/bin/bash

python3 Authorities.py & disown
# NOTE: need to be the same number of witnesses in config.ini
for i in `seq 0 39`; do
    python3 Witness.py "$i" & disown
done
sleep 2
python3 Customer_preprocessed.py & disown
python3 Merchant_witness_distributed.py

pkill -f Authorities.py
