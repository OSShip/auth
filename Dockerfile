FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY utils/ /app/utils/
COPY services/auth/ /app/services/auth/
WORKDIR /app/services/auth
RUN go mod download && CGO_ENABLED=0 go build -o /auth .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /auth /auth
EXPOSE 8081
CMD ["/auth"]
