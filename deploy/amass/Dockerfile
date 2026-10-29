FROM golang:1.27.3-alpine AS build
RUN apk --no-cache add git
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /amass ./cmd/amass
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/owasp-amass/amass" \
      org.opencontainers.image.revision="a284d25a890cbb561a53410080a3fd96bbaa7312" \
      io.jo.profile="crtsh-only-semaphore-one-v1"
RUN apk --no-cache add ca-certificates && adduser -D jo
COPY --from=build /amass /bin/amass
USER jo
ENV HOME=/tmp
WORKDIR /tmp
ENTRYPOINT ["/bin/amass"]
