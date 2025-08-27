FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Copy the built JAR file
COPY build/libs/*.jar app.jar

# Expose the port
EXPOSE 8080

# Run the application with optimized JVM flags for containers
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-Dcom.sun.management.jmxremote=false", "-Dcom.sun.management.jmxremote.port=0", "-Dcom.sun.management.jmxremote.authenticate=false", "-Dcom.sun.management.jmxremote.ssl=false", "-Djava.rmi.server.hostname=localhost", "-Dmanagement.metrics.export.prometheus.enabled=false", "-Dmanagement.endpoints.web.exposure.include=health,info", "-Dmanagement.endpoint.health.show-details=never", "-jar", "app.jar"]
