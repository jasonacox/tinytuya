FROM python:3.8
WORKDIR /app
RUN pip3 install --no-cache-dir tinytuya
COPY . .
CMD ["python3", "server.py"]
EXPOSE 8888 
EXPOSE 6666/udp
EXPOSE 6667/udp
