# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX=docker.io

# ---------- Build stage: package runnable testsuite artifacts ----------
FROM ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/library/maven:3.9.12-eclipse-temurin-21-alpine@sha256:8b2f036477a5bc9fbeb16cfb7301c484d7fff727b1c4907301ac665526bd7a8e AS build

WORKDIR /app
ARG SERENITY_CLI_VERSION=4.1.13
ARG GITLAB_BASE_URL=https://gitlab.com
ARG TESTPROXY_PROJECT_ID=75362233
ENV MAVEN_ARGS="-Dgitlab.base.url=${GITLAB_BASE_URL} -Dtestproxy.project.id=${TESTPROXY_PROJECT_ID}"

# Bring in the workspace.
COPY . .

# Package test-jar + test dependencies without executing the tests.
# Skip source-style checks here because CI already runs them separately and they
# are irrelevant for assembling the runtime image.
RUN --mount=type=secret,id=ci_job_token,required=false \
    . docker/build-common.sh && \
    tiger_export_ci_job_token && \
    mvn -s .m2/settings.xml -B -DskipTests=true -DskipITs=true \
      -Dlicense.skip=true -Dlicense.skipAddThirdParty=true -Dcheckstyle.skip=true \
      -Dmaven.repo.local=/tmp/.m2/repository \
      -Dtraceability.skip=true -Dtraceability.sync.skip=true -Dserenity.readme.sync.skip=true \
      package \
      org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
      -Dartifact=net.serenity-bdd:serenity-cli:${SERENITY_CLI_VERSION} \
      -DoutputDirectory=/app/serenity-cli

RUN . docker/build-common.sh && \
    tiger_verify_gitlab_testproxy_artifacts

# ---------- Runtime stage: run testsuite without Maven ----------
FROM ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}/library/eclipse-temurin:21-jre-alpine@sha256:704db3c40204a44f471191446ddd9cda5d60dab40f0e15c6507b815ed897238b AS runtime
ARG SERENITY_CLI_VERSION=4.1.13
ARG ZETA_UID=1000
ARG ZETA_GID=1000

WORKDIR /app

# Copy packaged artifacts.
RUN mkdir -p /app/tools
COPY --from=build /app/target/*-tests.jar /app/tests.jar
COPY --from=build /app/target/deps /app/libs
COPY --from=build /app/.cache/zeta-test-certificates /app/zeta-test-certificates
COPY --from=build /app/target/agent/tiger-java-agent.jar /app/agent/tiger-java-agent.jar
COPY --from=build /app/tiger.yaml /app/tiger.yaml
COPY --from=build /app/tiger-proxy.yaml /app/tiger-proxy.yaml
COPY --from=build /app/tiger /app/tiger
COPY --from=build /app/docs/asciidoc/tables/source/product_implementation.csv /app/docs/asciidoc/tables/source/product_implementation.csv
COPY --from=build /app/docs/asciidoc/testaspekte /app/docs/asciidoc/testaspekte
COPY --from=build /app/src/test/resources/tls-test-tool/certificates /app/src/test/resources/tls-test-tool/certificates
COPY --from=build /app/src/test/resources/mocks /app/src/test/resources/mocks
COPY --from=build /app/src/test/resources/keys /app/src/test/resources/keys
COPY --from=build /app/src/test/resources/schemas /app/src/test/resources/schemas
COPY --from=build /app/serenity-cli/serenity-cli-${SERENITY_CLI_VERSION}.jar /app/tools/serenity-cli.jar
COPY --from=build /app/docker/run-tests-common.sh /app/run-tests-common.sh
COPY docker/quality_gate/run-tests.sh /app/run-tests.sh
RUN chmod +x /app/run-tests.sh

# The TLS test tool fixture binary depends on Alpine's C/C++ runtime libraries.
RUN apk add --no-cache libgcc libstdc++

# Install kubectl only when the base image does not already provide it.
RUN . /app/run-tests-common.sh && \
    tiger_ensure_kubectl

RUN . /app/run-tests-common.sh && \
    tiger_prepare_nonroot_runtime "zeta" "zeta" "${ZETA_UID}" "${ZETA_GID}" /app /app/target

# Default runtime toggles; can be overridden at `docker run`.
ENV ZETA_BASE_URL="" \
    ZETA_PROXY_URL="" \
    ALLOW_DEPLOYMENT_MODIFICATION="" \
    OPENSEARCH_URL="" \
    ZETA_TEST_CERTIFICATES_DIR="/app/zeta-test-certificates" \
    PROFILE="" \
    CUCUMBER_TAGS="" \
    SERENITY_EXPORT_DIR="" \
    CUCUMBER_EXPORT_DIR="" \
    ALLURE_RESULTS_DIR="" \
    HOME="/home/zeta" \
    KUBECONFIG="/home/zeta/.kube/config"

USER zeta

ENTRYPOINT ["/app/run-tests.sh"]
