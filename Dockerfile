FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml /app/
COPY .mvn /app/.mvn
COPY mvnw /app/
COPY mvnw.cmd /app/

RUN ./mvnw -q -DskipTests dependency:go-offline

COPY src /app/src
RUN ./mvnw -q -DskipTests package

# ---- runtime stage ----
FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]