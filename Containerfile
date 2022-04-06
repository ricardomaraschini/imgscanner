# assemble a builder image
FROM docker.io/library/centos:7 AS builder

# install trivy. XXX we should use trivy as a go library instead of its binary.
RUN curl -L -o /tmp/trivy_0.25.3_Linux-64bit.tar.gz \
    https://github.com/aquasecurity/trivy/releases/download/v0.25.3/trivy_0.25.3_Linux-64bit.tar.gz
RUN tar -C /tmp -zxvf /tmp/trivy_0.25.3_Linux-64bit.tar.gz
RUN mv /tmp/trivy /usr/local/bin

# install go
RUN curl -L -o /tmp/go1.18.linux-amd64.tar.gz https://go.dev/dl/go1.18.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.18.linux-amd64.tar.gz
RUN ln -s /usr/local/go/bin/go /usr/local/bin

# install build dependencies and build imgscanner
RUN yum install -y git make
WORKDIR /src
ARG version
ENV VERSION=${version:-v0.0.0}
COPY . .
RUN make imgscanner

# application
FROM docker.io/library/centos:7
COPY --from=builder /src/output/bin/imgscanner /usr/local/bin/imgscanner
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
ENTRYPOINT [ "/usr/local/bin/imgscanner" ]
