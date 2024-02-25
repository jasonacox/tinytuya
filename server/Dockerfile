FROM python:3.10
WORKDIR /app
# Install Rust for cryptography (remove pycryptodome)
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install --no-cache-dir tinytuya
COPY . .
CMD ["python3", "server.py"]
EXPOSE 8888
EXPOSE 6666/udp
EXPOSE 6667/udp
