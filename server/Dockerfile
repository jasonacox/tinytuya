FROM python:3.12-bookworm
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir cryptography pycryptodome
RUN pip install --no-cache-dir netifaces tinytuya psutil colorama requests
COPY . .
CMD ["python3", "server.py"]
EXPOSE 8888
EXPOSE 6666/udp
EXPOSE 6667/udp
EXPOSE 7000/udp
