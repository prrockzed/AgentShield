### Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /sandbox-manager ./cmd/sandbox-manager

### Run stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /sandbox-manager /sandbox-manager

EXPOSE 8002

CMD ["/sandbox-manager"]
