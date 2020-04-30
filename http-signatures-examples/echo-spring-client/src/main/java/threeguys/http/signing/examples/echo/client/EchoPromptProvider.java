package threeguys.http.signing.examples.echo.client;

import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStyle;
import org.springframework.shell.jline.PromptProvider;
import org.springframework.stereotype.Component;

@Component
public class EchoPromptProvider implements PromptProvider {

    @Override
    public AttributedString getPrompt() {
        return new AttributedString("(echo-shell)$ ",
                AttributedStyle.DEFAULT.foreground(AttributedStyle.BLUE));
    }

}
