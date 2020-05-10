FROM openjdk:11-jre

RUN mkdir -p /usr/app/lib
ADD target/lib /usr/share/lib
ARG JAR_FILE
ADD target/${JAR_FILE} /usr/share/lib/echo-netty-server.jar
