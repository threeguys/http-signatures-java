FROM openjdk:11-jre

RUN mkdir -p /usr/app/lib
ADD target/lib /usr/app/lib
ARG JAR_FILE
ADD target/${JAR_FILE} /usr/app/lib/echo-netty-server.jar

WORKDIR /usr/app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "lib/echo-netty-server.jar"]
