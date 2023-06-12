#
#
# Image versions
ARG BASE_BUILDER=python:3.10.11-slim-bullseye
ARG BASE_IMAGE=python:3.10.11-slim-bullseye


#
#
# Base builder
FROM ${BASE_BUILDER} as builder
ARG TARGETARCH
ARG BIN_OUTPUT="/usr/local/bin"

ARG HELM_VERSION=3.11.1
ARG TERRAFORM_VERSION="1.4.6"
ARG KUBECTL_VERSION="1.27.1"

# update the image and install some packages
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    apt-transport-https \
    software-properties-common \
    ca-certificates \
    lsb-release \
    curl unzip jq

# HELM
RUN : \
    && echo "HELM_VERSION: ${HELM_VERSION}" \
    && DESIRED_VERSION="v${HELM_VERSION}" \
    && curl "https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3" | bash

# Terraform
RUN : \
    && echo "TERRAFORM_VERSION: ${TERRAFORM_VERSION}" \
    && TMPFILE=$(mktemp) \
    && LATEST_TERRAFORM_URL=$(curl -sL https://releases.hashicorp.com/terraform/index.json | jq -r '.versions[].builds[].url' | grep -E -v 'rc|beta|alpha' | grep -E "linux.*${TARGETARCH}" | grep -E "${TERRAFORM_VERSION}" | tail -1) \
    && curl -sSL "$LATEST_TERRAFORM_URL" -o "$TMPFILE" \
    && unzip -d "$BIN_OUTPUT" "$TMPFILE" \
    && rm "$TMPFILE" 

# KUBECTL
# install Kubectl
# latest $(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)
RUN : \
    && echo "KUBECTL_VERSION: ${KUBECTL_VERSION}" \
    && curl -Lo ${BIN_OUTPUT}/kubectl "https://storage.googleapis.com/kubernetes-release/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x ${BIN_OUTPUT}/kubectl

# AWS-CLI
RUN : \
    && echo "== AWS-CLI installation" \
    && TMPFILE=$(mktemp) \
    && arch=`echo ${TARGETARCH} | sed -e 's/amd64/x86_64/' -e 's/arm64/aarch64/'` \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "$TMPFILE" \
    && unzip -d /tmp "$TMPFILE" \
    && ./tmp/aws/install -i /usr/local/aws-cli -b /usr/local/bin \
    && rm "$TMPFILE"



FROM ${BASE_IMAGE}
COPY requirements.txt /tmp/requirements.txt

# update the image and install some packages
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        apt-transport-https \
        software-properties-common \
        ca-certificates \
        lsb-release \
        curl unzip jq sudo gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io \
    && apt-get upgrade -y && apt-get full-upgrade -y \
    && pip install --upgrade pip \
    && pip3 install --no-cache-dir -r /tmp/requirements.txt \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* \
    && apt-get autoremove -y \
    && apt-get clean

RUN useradd -ms /bin/bash fcs && echo "fcs:fcs" | chpasswd && adduser fcs sudo && usermod -a -G docker "fcs"

# Copying builder binaries to this image
COPY --from=builder /usr/local/aws-cli /usr/local/aws-cli
COPY --from=builder /usr/local/bin/kubectl /usr/local/bin/helm /usr/local/bin/terraform /usr/local/bin/

# linking the AWS-CLI to the execution path
RUN : \
    && ln -sf /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws \
    && ln -sf /usr/local/aws-cli/v2/current/bin/aws_completer /usr/local/bin/aws_completer

COPY . /fcs

# Creating a direct link to fcs root script
RUN ln -sf /fcs/fcs.py /usr/local/bin/fcs

USER fcs 
CMD ["/bin/bash"]