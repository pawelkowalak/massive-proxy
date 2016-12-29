FROM alpine:3.4
RUN apk add --no-cache ca-certificates
RUN mkdir -p /certs
ADD massive-proxy /
VOLUME /certs
EXPOSE 80 443
ENTRYPOINT ["/massive-proxy"]