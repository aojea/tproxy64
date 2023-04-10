ARG GOARCH="amd64"
FROM golang:1.20 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/tproxy64 .

FROM registry.k8s.io/build-image/distroless-iptables:v0.2.1
COPY --from=builder --chown=root:root /go/bin/tproxy64 /bin/tproxy64
CMD ["/bin/tproxy64"]
