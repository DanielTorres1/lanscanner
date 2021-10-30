FROM python:3.6.5-alpine

ADD requirements.txt ./
ADD *.py ./
ADD *.yaml ./
ADD DumpsterDiver.sh ./
RUN pip install --no-cache-dir -r requirements.txt && \
    chmod +x DumpsterDiver.py && \
    chmod +x DumpsterDiver.sh && \
    mkdir -p /var/log/dumpsterdiver

ENTRYPOINT ["/DumpsterDiver.sh"]
