FROM openjdk:21-jdk-slim
LABEL authors="Artur"
WORKDIR /auth-server
COPY ./target/AuthorizationServer-1.0.jar .
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8090

CMD ["java", "-jar", "AuthorizationServer-1.0.jar"]