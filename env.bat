@echo off

echo Setting persistent environment variables...
setx SCP_OVERRIDE 0
setx SCP_REMOTE_IP 192.168.157.133
setx SCP_REMOTE_USER user
setx SCP_REMOTE_PATH /mnt/c/Users/IEUser/Desktop
setx SCP_PRE_DELETE ""

REM Second set lets us call from build.bat if user forgot to reboot
set SCP_OVERRIDE=0
set SCP_REMOTE_IP=192.168.157.133
set SCP_REMOTE_USER=user
set SCP_REMOTE_PATH=/mnt/c/Users/IEUser/Desktop
set SCP_PRE_DELETE=""

echo Done. Now please reboot your machine so the environment variables are taken into account.
