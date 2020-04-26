package threeguys.http.signing.spring;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import threeguys.http.signing.servlet.HttpSignatureVerifierFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpSignatureHandlerInterceptor extends HandlerInterceptorAdapter {

    private HttpSignatureVerifierFilter filter;

    public HttpSignatureHandlerInterceptor(HttpSignatureVerifierFilter filter) {
        super();
        this.filter = filter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        boolean result = filter.doFilter(request);
        System.err.println("INSIDE PREHANDLE! " + result);
        return result;
    }

}
