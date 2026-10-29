FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends g++ cmake make libsqlite3-dev libssl-dev libcurl4-openssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend backend
COPY frontend frontend
COPY database database
RUN cmake -S backend -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
ENV DB_PATH=/data/eventsphere.db CERT_DIR=/data/certificates PORT=8080
CMD ["sh","-c","mkdir -p /data && ./build/eventsphere"]
