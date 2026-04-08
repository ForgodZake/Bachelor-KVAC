FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

WORKDIR /workspace
ENV PYTHONPATH=/workspace/src

# Base dependencies
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
    curl \
    vim \
    nano \
    less \
    pkg-config \
    flex \
    bison \
    m4 \
    libgmp-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build and install PBC from source
RUN wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz && \
    tar xzf pbc-1.0.0.tar.gz && \
    cd pbc-1.0.0 && \
    ./configure LDFLAGS="-lgmp" && \
    make && \
    make install && \
    ldconfig && \
    cd / && \
    rm -rf /pbc-1.0.0 /pbc-1.0.0.tar.gz

# Build and install Charm
RUN git clone https://github.com/JHUISI/charm.git /tmp/charm && \
    cd /tmp/charm && \
    ./configure.sh && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /tmp/charm

# Create a container-local virtual environment
RUN python3 -m venv /opt/venv --system-site-packages
ENV PATH="/opt/venv/bin:${PATH}"

# Upgrade pip tooling inside the venv
RUN pip install --upgrade pip setuptools wheel pytest

# Optional: create a non-root user for development
RUN useradd -ms /bin/bash devuser && \
    chown -R devuser:devuser /workspace

USER devuser

# Default shell for development
CMD ["/bin/bash"]