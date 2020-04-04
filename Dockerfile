FROM registry.access.redhat.com/ubi8-minimal

ENV KEYCLOAK_VERSION 9.0.2
ENV JDBC_POSTGRES_VERSION 42.2.5

ENV LAUNCH_JBOSS_IN_BACKGROUND 1
ENV PROXY_ADDRESS_FORWARDING false
ENV JBOSS_HOME /opt/jboss/keycloak
ENV LANG en_US.UTF-8

USER root

#ADD distribution/server-dist/target/keycloak-$KEYCLOAK_VERSION.tar.gz /source

COPY distribution/server-dist/target/keycloak-$KEYCLOAK_VERSION /opt/jboss/keycloak
COPY tools/patch/layers.conf /opt/jboss/keycloak/modules

RUN microdnf update -y && microdnf install -y glibc-langpack-en gzip hostname java-11-openjdk-headless openssl tar which && microdnf clean all

ADD tools /opt/jboss/tools
RUN /opt/jboss/tools/build-keycloak.sh

USER 1000

EXPOSE 8080
EXPOSE 8443

ENTRYPOINT [ "/opt/jboss/tools/docker-entrypoint.sh" ]

CMD ["-b", "0.0.0.0"]
