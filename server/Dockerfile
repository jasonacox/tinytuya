FROM python:3.8-alpine
WORKDIR /app
RUN pip3 install tinytuya
COPY . .
CMD ["python3", "server.py"]
EXPOSE 8888 
