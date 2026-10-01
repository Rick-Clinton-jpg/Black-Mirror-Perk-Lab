import os
p='/tmp/black-mirror-doors-live-20261001/run-02/raw-canary.txt'
fd=os.open(p,os.O_WRONLY|os.O_TRUNC)
os.write(fd,b'BREACH\n')
