FROM ubuntu

RUN apt-get update && apt-get install -y xxd lldb gdb python3 python3-pip gdbserver netcat strace unzip
RUN python3 -m pip install prompt_toolkit

RUN mkdir -p wasp-server

COPY wasp wasp-server

COPY wasp-malware wasp-malware
COPY deployment-scripts deployment-scripts

RUN adduser malware

CMD ./wasp-server/server.py

USER malware

RUN cp /wasp-malware/*.localhost.patched /tmp
RUN mkdir -p ~/.wasp/base_build ~/.wasp/base_deployment_scripts
RUN cp /wasp-malware/* ~/.wasp/base_build/
RUN cp /deployment-scripts/* ~/.wasp/base_deployment_scripts/
RUN chmod +x /tmp/*.localhost.patched
