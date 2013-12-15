package org.plovr.cli;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * {@link HttpServerUtil} is a collection of utilities for dealing with
 * {@link HttpServer} objects.
 *
 * @author bolinfest@gmail.com (Michael Bolin)
 */
public final class HttpServerUtil {

  private final static String KEYSTORE = "keystore.jks";
  private final static char[] PASSPHRASE = "secureplovr".toCharArray();

  /** Utility class: do not instantiate. */
  private HttpServerUtil() {}

  public static void printListeningStatus(HttpServer server) {
    InetSocketAddress serverAddress = server.getAddress();
    System.err.println("Listening on " + serverAddress);
  }

  public static HttpServer create(InetSocketAddress addr, int backlog, boolean isHttps) throws IOException {
    if (isHttps) {
      HttpsServer server = HttpsServer.create(addr, backlog);

      KeyStore keystore = null;
      KeyManagerFactory keyManagerFactory = null;
      TrustManagerFactory trustManagerFactory = null;
      SSLContext sslContext = null;

      try {
        // try loading KeyStore
        InputStream keyStream = ClassLoader.getSystemResourceAsStream(KEYSTORE);
        keystore = KeyStore.getInstance("JKS");
        keystore.load(keyStream, PASSPHRASE);
        keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keystore, PASSPHRASE);
        trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keystore);

        // Initialise SSL Context
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

      } catch (IOException e) {
        System.err.println("Failed loading KeyStore");
      } catch (Exception e) {
        System.err.println("Failed setting SSL Context: " + e.getMessage());
      }

      // set configuration for SSL connections
      server.setHttpsConfigurator (new HttpsConfigurator(sslContext) {
        public void configure(HttpsParameters params) {
          SSLContext sslContext = getSSLContext();
          SSLParameters sslParams = sslContext.getDefaultSSLParameters();
          params.setSSLParameters(sslParams);

        }
      });

      return server;
    } else {
      return HttpServer.create(addr, backlog);
    }
  }
}
