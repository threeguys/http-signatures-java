package threeguys.http.signing.spring;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class DemoController {

    @RequestMapping("/")
    public @ResponseBody String helloWorld(@RequestParam("name") String name) {
        System.err.println("RUNNING IN HELLO WORLD!");
        return "Hello, " + name + "!";
    }

}
