FROM ubuntu

RUN apt-get update && apt-get install -y xxd lldb gdb python3 gdbserver netcat

RUN mkdir -p wasp-server

COPY generate_config.py wasp-server
COPY server.py wasp-server

COPY wasp-malware wasp-malware

RUN adduser malware

CMD ./wasp-server/server.py

USER malware

RUN cp /wasp-malware/*.localhost /tmp
RUN chmod +x /tmp/*.localhost
