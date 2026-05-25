FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY src/agent-registry/go.mod src/agent-registry/go.sum ./
RUN go mod download
COPY src/agent-registry/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o agent-registry .

FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/agent-registry .
ENV USER_DATA_DIR=/app/user-data
ENV REGISTRY_ADDR=:5000
EXPOSE 5000
VOLUME /app/user-data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5000/_mgmt/health || exit 1
ENTRYPOINT ["./agent-registry"]
CMD ["serve"]
