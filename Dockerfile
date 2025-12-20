FROM golang:1.24.2-alpine AS builder
RUN apk add --no-cache curl
WORKDIR /app
COPY . .
RUN curl -s https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf -o ./service/disposable_email_blocklist.conf
RUN go mod download
RUN go build -o ./api-server ./main.go


FROM alpine:latest AS runner
WORKDIR /app
COPY --from=builder /app/api-server .
EXPOSE 3000
ENTRYPOINT ["./api-server"]
