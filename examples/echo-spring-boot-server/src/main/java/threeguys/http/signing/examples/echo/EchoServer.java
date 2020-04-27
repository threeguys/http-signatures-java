package threeguys.http.signing.examples.echo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import threeguys.http.signing.spring.HttpSignatureHandlerInterceptor;

@SpringBootApplication
@ComponentScan({
        "threeguys.http.signing.spring.config.server",
        "threeguys.http.signing.examples.echo"
})
public class EchoServer {

    @Component
    public class WebConfig implements WebMvcConfigurer {

        @Autowired
        private HttpSignatureHandlerInterceptor interceptor;

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor).addPathPatterns("/echo");
        }

    }

    public static void main(String [] args) {
        SpringApplication.run(EchoServer.class, args);
    }

}
