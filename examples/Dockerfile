# Python base
FROM python:3.10

# Set the working directory
WORKDIR /app

# Update default packages
RUN apt-get update

# Get Ubuntu packages
RUN apt-get install -y \
    build-essential \
    curl

# Update new packages
RUN apt-get update

# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install dependencies
COPY entrypoint.sh /bin/entrypoint.sh
RUN curl https://sh.rustup.rs -sSf |sh -s -- -y
RUN pip3 install --no-cache-dir tinytuya

# Allow UDP traffic 6666, 6667 and 7000
EXPOSE 6666/udp
EXPOSE 6667/udp
EXPOSE 7000/udp

# Run the application bash entrypoint.sh
ENTRYPOINT ["/bin/entrypoint.sh"]

# Example Docker build
# docker build -t jasonacox/tinytuya-cli:latest .

# Example Docker run but with host network
# docker run \
# -it --rm \
# -p 6666:6666/udp \
# -p 6667:6667/udp \
# -p 7000:7000/udp \
# -v $(pwd):/app \
# --name tinytuya-cli \
# jasonacox/tinytuya-cli:latest
