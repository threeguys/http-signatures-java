/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import threeguys.http.signing.examples.server.InMemoryKeyProvider;
import threeguys.http.signing.examples.server.ServerHelper;
import threeguys.http.signing.spring.HttpSignatureHandlerInterceptor;
import threeguys.http.signing.spring.config.SignaturesConfiguration;
import threeguys.http.signing.spring.config.server.HttpVerifierConfiguration;

@SpringBootApplication
@Import({ SignaturesConfiguration.class, HttpVerifierConfiguration.class })
public class EchoServer {

    @Component
    public static class WebConfig implements WebMvcConfigurer {

        @Autowired
        private HttpSignatureHandlerInterceptor interceptor;

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor).addPathPatterns("/echo");
        }

    }

    @Configuration
    public static class AppConfig {

        @Bean
        public InMemoryKeyProvider keyProvider() {
            return new InMemoryKeyProvider();
        }

        @Bean
        public ServerHelper helper() {
            return new ServerHelper();
        }

    }

    public static void main(String [] args) {
        SpringApplication.run(EchoServer.class, args);
    }

}
