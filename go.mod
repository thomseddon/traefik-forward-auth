module github.com/thomseddon/traefik-forward-auth

go 1.14

require (
	github.com/Azure/go-autorest v11.1.2+incompatible // indirect
	github.com/Jeffail/gabs/v2 v2.5.1
	github.com/aliyun/aliyun-oss-go-sdk v0.0.0-20190307165228-86c17b95fcd5 // indirect
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/containous/traefik/v2 v2.2.8
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/decker502/dnspod-go v0.2.0 // indirect
	github.com/go-ini/ini v1.44.0 // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/gravitational/trace v1.1.11 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/jonboulle/clockwork v0.2.0 // indirect
	github.com/miekg/dns v1.1.31 // indirect
	github.com/opencontainers/runc v1.0.0-rc8 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.5.1
	github.com/thomseddon/go-flags v1.4.1-0.20190507184247-a3629c504486
	github.com/transip/gotransip v5.8.2+incompatible // indirect
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de // indirect
	golang.org/x/net v0.0.0-20200707034311-ab3426394381 // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200728102440-3e129f6d46b1 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
)

// From traefik
replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v12.4.1+incompatible
	github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20180112153951-65b0cdae8d7f
	github.com/docker/docker => github.com/docker/engine v1.4.2-0.20191113042239-ea84732a7725
	github.com/go-check/check => github.com/containous/check v0.0.0-20170915194414-ca0bf163426a
	github.com/gorilla/mux => github.com/containous/mux v0.0.0-20181024131434-c33f32e26898
	github.com/mailgun/minheap => github.com/containous/minheap v0.0.0-20190809180810-6e71eb837595
	github.com/mailgun/multibuf => github.com/containous/multibuf v0.0.0-20190809014333-8b6c9a7e6bba
	github.com/rancher/go-rancher-metadata => github.com/containous/go-rancher-metadata v0.0.0-20190402144056-c6a65f8b7a28
)
