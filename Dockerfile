# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /submcp ./cmd/submcp

# Runtime stage (alpine: provides wget for the healthcheck)
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget \
    && adduser -D -u 10001 submcp
COPY --from=builder /submcp /submcp
# P2-8: run as non-root (least privilege; the container only serves HTTP).
USER submcp
EXPOSE 12008
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:12008/health || exit 1
ENTRYPOINT ["/submcp"]
