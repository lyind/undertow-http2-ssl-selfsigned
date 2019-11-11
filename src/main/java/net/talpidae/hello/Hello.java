package net.talpidae.hello;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.util.Headers;
import lombok.val;
import net.talpidae.ssl.DummySslContextFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;


public class Hello
{
    /**
     * Launch "hello" Undertow HTTP2 server on a dynamically allocated port.
     * <p>
     * The server will use a self-signed certificate loaded from the keystore "keystore.pfx" (PKCS12) in the working directory.
     */
    public static void main(String[] args)
    {
        val builder = Undertow.builder();

        builder.setServerOption(UndertowOptions.ENABLE_STATISTICS, false);
        builder.setServerOption(UndertowOptions.IDLE_TIMEOUT, (int) TimeUnit.MINUTES.toMillis(6));
        builder.setServerOption(UndertowOptions.NO_REQUEST_TIMEOUT, (int) TimeUnit.MINUTES.toMillis(5));
        builder.setServerOption(UndertowOptions.ENABLE_HTTP2, true);

        val sslContextFactory = new DummySslContextFactory();
        try
        {
            builder.addHttpsListener(0, "0.0.0.0", sslContextFactory.createSslContext());
        }
        catch (IOException e)
        {
            throw new RuntimeException("Failed to create SSL context: " + e.getMessage(), e);
        }

        // a simple handler returning "Hello" with graceful shutdown capability
        builder.setHandler(Handlers.gracefulShutdown(exchange -> {
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
            exchange.getResponseSender().send("Hello");
        }));

        final Undertow server = builder.build();
        server.start();

        for (val info : server.getListenerInfo())
        {
            if (info.getAddress() instanceof InetSocketAddress)
            {
                System.err.println("server running at " + ((InetSocketAddress) info.getAddress()).getHostString() + ":" + ((InetSocketAddress) info.getAddress()).getPort());
            }
        }
    }
}
