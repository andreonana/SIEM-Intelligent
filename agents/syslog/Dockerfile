FROM python:3.12-slim

WORKDIR /agent

# stdlib Python uniquement — aucune dépendance à installer
COPY syslog_receiver.py .

EXPOSE 5140/udp
EXPOSE 5140/tcp
EXPOSE 8090

CMD ["python3", "syslog_receiver.py"]
