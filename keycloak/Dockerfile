FROM quay.io/keycloak/keycloak:25.0

WORKDIR /opt/keycloak

COPY /theme /opt/keycloak/providers/

# Plain-folder themes, readable in review: the WiseFood email theme inherits
# the Keycloakify jar above and replaces the email frame and wording.
COPY /themes /opt/keycloak/themes/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--features=token-exchange"]
