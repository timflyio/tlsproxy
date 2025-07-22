# docker build -t timflyio/tlsproxy .
# docker push timflyio/tlsproxy
# ----
ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
RUN go build -v -o tlsproxy main.go

# ----
FROM debian:bookworm

COPY --from=builder /usr/src/app/tlsproxy /usr/local/bin/

WORKDIR /etc
CMD ["tlsproxy"]
