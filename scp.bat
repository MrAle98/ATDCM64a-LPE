@echo off
REM Assumes the following:
REM - current path is PWD (e.g. when running it from Visual Studio Build Events)
REM - PuTTY (which contains Windows scp) is installed
REM - a PuTTY profile session is saved as the ip "x.x.x.x", so pscp (which is 
REM   called by scp.bat) will attempt to use the saved session, and thus 
REM   key, by default.
REM   In order to have pscp.exe use a key by default associated with the host, 
REM   you need to generate a private key *.ppk (using puttygen) and then associated
REM   the key with a "Saved Session" with the IP address as the name "x.x.x.x". You specify it
REM   under Connection->SSH->Auth and just point it at the *.ppk file you generated. 
REM   As long as the session is saved as the ip "x.x.x.x", then pscp (which is 
REM   called by scp.bat) will attempt to use the saved session, and thus 
REM   key, by default.
REM - (optional) You can use Pageant to avoid having to input your SSH key password every time
REM - env.bat was executed in order to define the following environment variables: SCP_OVERRIDE,
REM   SCP_REMOTE_IP, SCP_REMOTE_USER, SCP_REMOTE_PATH, SCP_PRE_DELETE

IF %SCP_OVERRIDE%==1 (
    goto BuildEventOK
)

IF "%SCP_REMOTE_PATH%"=="" (
    echo You didn't specify SCP_REMOTE_PATH, so defaulting to '.'
    set SCP_REMOTE_PATH="."
)

IF "%SCP_REMOTE_IP%"=="" (
    echo You need to define SCP_REMOTE_IP, please execute env.bat
    goto BuildEventFailed
)
IF "%SCP_REMOTE_USER%"=="" (
    echo You need to define SCP_REMOTE_USER, please execute env.bat
    goto BuildEventFailed
)

echo [scp] Copying all files to the remote host: %SCP_REMOTE_IP% with user: %SCP_REMOTE_USER%

IF "%1"=="" (
    echo Usage: scp.bat ^<files^>
    echo    ^<files^> comma separated list of files to copy over ssh
    goto BuildEventFailed
)
set files=%1%

for %%I in (%files%) do (
    if not exist %%I (
        REM echo %%I does not exist, should not happen if not a pdb
        REM goto next
        echo %%I does not exist
        goto BuildEventFailed
    )
    echo [scp] Copying %%I

    IF NOT "%SCP_PRE_DELETE%"=="" (
        REM When I scp to the Windows 10 WSL openssh server I can't overwrite the 
        REM destination path even though my user has permissions. I can however
        REM delete. So this is my hacky way of doing it. %%~nxI gives us just the 
        REM filename without paths
        echo Running pre-delete hack
        echo rm %SCP_REMOTE_PATH%/%%~nxI > putty_cmd.txt
        "C:\Program Files\PuTTy\putty.exe" -ssh -load %SCP_REMOTE_IP% -m putty_cmd.txt
        del putty_cmd.txt
    )

    "C:\Program Files\PuTTY\pscp.exe" -l %SCP_REMOTE_USER% %%I %SCP_REMOTE_IP%:%SCP_REMOTE_PATH%

    if errorlevel 1 goto BuildEventFailed
    :next
    echo ""
)

REM http://geekswithblogs.net/dchestnutt/archive/2006/05/30/80113.aspx
REM unless the final step exits with an error code
goto BuildEventOK

:BuildEventFailed
echo [scp] FAILED
exit /B 1 

:BuildEventOK
echo [scp] COMPLETED OK
