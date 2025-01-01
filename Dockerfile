FROM golang:1.23.4-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o ./forntend-api ./main.go


FROM alpine:latest AS runner
WORKDIR /app
COPY --from=builder /app/frontend-api .
EXPOSE 3000
ENTRYPOINT ["./frontend-api"]
