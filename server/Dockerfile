FROM python:3.12-bookworm
WORKDIR /app
ENV PYTHONUNBUFFERED 1
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
RUN pip3 install cryptography pycryptodome --no-build-isolation
RUN pip3 install --no-cache-dir tinytuya
COPY . .
CMD ["python3", "server.py"]
EXPOSE 8888
EXPOSE 6666/udp
EXPOSE 6667/udp
