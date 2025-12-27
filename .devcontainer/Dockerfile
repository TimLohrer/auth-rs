FROM mcr.microsoft.com/devcontainers/base:bookworm

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default --component rustfmt,clippy \
    && echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

# Install Node.js LTS
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Bun
RUN curl -fsSL https://bun.sh/install | bash \
    && echo 'export BUN_INSTALL="$HOME/.bun"' >> $HOME/.bashrc \
    && echo 'export PATH="$BUN_INSTALL/bin:$PATH"' >> $HOME/.bashrc

ENV CARGO_HOME=/root/.cargo
ENV RUSTUP_HOME=/root/.rustup
ENV PATH="/root/.cargo/bin:/root/.bun/bin:${PATH}"
ENV BUN_INSTALL=/root/.bun

