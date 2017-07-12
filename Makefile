REV = $(shell git describe --always)

build:
	GOOS=linux GOARCH=amd64 go build
	docker build -t viru/massive-proxy:$(REV) .
	docker save -o massive_proxy_${REV}.tar viru/massive-proxy:$(REV)
	rm massive-proxy
	sed 's/REV/$(REV)/' massive-proxy.service.tmpl > massive-proxy.service

deploy:
	scp massive_proxy_${REV}.tar massive-proxy.service hd1:
	ssh hd1 "fleetctl destroy massive-proxy.service && fleetctl start massive-proxy.service && fleetctl status massive-proxy.service"
