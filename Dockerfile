# Stage 1: Build the tool
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
RUN git clone https://github.com/bitquark/shortscan.git .
# Build just the main command
RUN go build -o /shortscan ./cmd/shortscan

# Stage 2: Minimal runtime image
FROM alpine:3.20

# Copy CA certificates from builder (needed for HTTPS)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /shortscan /usr/local/bin/shortscan

ENTRYPOINT ["shortscan"]
