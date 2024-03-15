FROM golang:1.22.0-alpine3.19 as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /go/bin/app

# Path: Dockerfile
FROM alpine:3.19 as runner

COPY --from=builder /go/bin/app /app

EXPOSE 8089
CMD ["/app"]
