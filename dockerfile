FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-wheel \
    git \
    wget \
    flex \
    bison \
    m4 \
    libgmp-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz && \
    tar xzf pbc-1.0.0.tar.gz && \
    cd pbc-1.0.0 && \
    ./configure LDFLAGS="-lgmp" && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf pbc-1.0.0 pbc-1.0.0.tar.gz

RUN git clone https://github.com/JHUISI/charm.git /tmp/charm && \
    cd /tmp/charm && \
    ./configure.sh && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /tmp/charm

COPY . /app

CMD ["python3", "src/main.py"]