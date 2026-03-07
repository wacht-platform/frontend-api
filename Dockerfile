FROM golang:1.26.0-alpine AS builder
RUN apk add --no-cache curl
WORKDIR /app
COPY . .
RUN curl -s https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf -o ./service/disposable_email_blocklist.conf
RUN go mod download
RUN go build -o ./api-server ./main.go


FROM alpine:latest AS runner
WORKDIR /app
RUN apk add --no-cache curl gnupg wget && \
    (curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh || wget -t 3 -qO- https://cli.doppler.com/install.sh) | sh
COPY --from=builder /app/api-server .
EXPOSE 3000
ENTRYPOINT ["doppler", "run", "--", "./api-server"]
