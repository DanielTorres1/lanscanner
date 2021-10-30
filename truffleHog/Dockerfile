FROM python:3-alpine
RUN apk add --no-cache git && pip install gitdb2==3.0.0 trufflehog
RUN adduser -S truffleHog
USER truffleHog
WORKDIR /project
COPY truffle-exclude.txt /etc/
COPY truffle-rules.json /etc/
COPY trufflehog-parser.py /usr/bin
COPY trufflehog.sh /usr/bin
ENTRYPOINT [ "/usr/bin/trufflehog.sh" ]
