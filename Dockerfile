# VULN 1: Unpinned, mutable base image tag — build is not reproducible and can
# silently pull a compromised image.
FROM node:latest

# VULN 2: Hardcoded secrets baked into image layers (recoverable via history).
ARG NPM_TOKEN=npm_9f8e7d6c5b4a3c2b1a0z
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

WORKDIR /app
COPY . .

# VULN 3: Remote script piped straight into a shell (supply-chain RCE, no
# integrity check).
RUN curl -sL http://get.example.com/install.sh | bash

# VULN 4: ADD from a remote URL — unverified download that is auto-extracted.
ADD http://downloads.example.com/tool.tar.gz /opt/tool/

RUN npm install

# VULN 5: No USER directive — the container runs as root.
EXPOSE 3000
CMD ["node", "server.js"]
