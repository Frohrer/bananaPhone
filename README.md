# bananaPhone
Create and send TCP custom packets

## Usage:
Run bananaPhone.py as root
```
sudo python3 bananaPhone.py
```

You can then change the TCP header information, such as the flags and sequences. This can be used to flood a target with SYN packets... not advised.

## Credit:
Initial code was taken from here: https://www.binarytides.com/raw-socket-programming-in-python-linux/

## Challenges:
All Bitwise operations had to be rewritten for Python 3 as they were calculated as strings.
