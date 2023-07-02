FROM ubuntu

RUN apt-get update && apt-get install -y xxd lldb gdb python3 python3-pip gdbserver netcat strace
RUN python3 -m pip install prompt_toolkit

RUN mkdir -p wasp-server

COPY generate_config.py wasp-server
COPY wasp wasp-server

COPY wasp-malware wasp-malware

RUN adduser malware

CMD ./wasp-server/server.py

USER malware

RUN cp /wasp-malware/*.localhost.patched /tmp
RUN chmod +x /tmp/*.localhost.patched
