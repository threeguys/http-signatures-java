FROM openjdk:11-jre-slim

RUN mkdir -p /usr/app/lib
COPY target/lib /usr/app/lib
COPY target/echo-netty-server-0.1-SNAPSHOT.jar /usr/app/lib/echo-netty-server-0.1-SNAPSHOT.jar

WORKDIR /usr/app
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "lib/echo-netty-server-0.1-SNAPSHOT.jar"]
