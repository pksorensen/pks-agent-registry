FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o agent-registry .

FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/agent-registry .
ENV USER_DATA_DIR=/data
ENV REGISTRY_ADDR=:5000
EXPOSE 5000
VOLUME /data
ENTRYPOINT ["./agent-registry"]
CMD ["serve"]
