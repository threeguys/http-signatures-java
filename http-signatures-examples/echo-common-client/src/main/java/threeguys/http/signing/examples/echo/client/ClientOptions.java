/** Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/ */
package threeguys.http.signing.examples.echo.client;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

public class ClientOptions {

    private static final Log log = LogFactory.getLog(ClientOptions.class);

    public static final String HOST = "host";
    public static final String PORT = "port";
    public static final String KEY = "key";
    public static final String PATH = "path";
    public static final String BODY = "body";

    public static final String DEFAULT_PATH = "/echo";
    public static final String DEFAULT_KEY = "echo-client";
    public static final String DEFAULT_HOST = "localhost";
    public static final short DEFAULT_PORT = 8080;

    private final String keyPrefix;
    private final String host;
    private final short port;
    private final String path;
    private final String body;

    public ClientOptions(String [] args) throws ParseException {
        final Options options = new Options();
        options.addOption(Option.builder(KEY)
                .hasArg()
                .desc("set the key file name, generates the key if it doesn't exist")
                .build());
        options.addOption(Option.builder(HOST)
                .hasArg()
                .desc("name/address of the server")
                .build());
        options.addOption(Option.builder(PORT)
                .hasArg()
                .type(Short.class)
                .desc("port of the server")
                .build());
        options.addOption(Option.builder(PATH)
                .hasArg()
                .desc("url to request")
                .build());
        options.addOption(Option.builder(BODY)
                .hasArg()
                .desc("path to file containing the body of the request")
                .build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        this.keyPrefix = cmd.getOptionValue(KEY, DEFAULT_KEY);
        this.host = cmd.getOptionValue(HOST, DEFAULT_HOST);
        this.port = getOptionValue(cmd, PORT, DEFAULT_PORT);
        this.path = cmd.getOptionValue(PATH, DEFAULT_PATH);
        this.body = cmd.getOptionValue(BODY, null);
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }

    public String getHost() {
        return host;
    }

    public short getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getBody() {
        return body;
    }

    public boolean hasBody() {
        return body != null;
    }

    private static <T> T getOptionValue(CommandLine cmd, String option, T defaultValue) throws ParseException {
        return (cmd.hasOption(option))
            ? (T) cmd.getParsedOptionValue(option)
                : defaultValue;
    }

    public static String setKeyId() throws UnknownHostException {
        String hostAddress = InetAddress.getLocalHost().getHostAddress();
        String keyId = "echo(" + hostAddress + "-" + new Random().nextInt(100000) + ")";
        System.setProperty("signer.keyId", keyId);
        log.info("Client key id: " + keyId);
        return keyId;
    }

}
