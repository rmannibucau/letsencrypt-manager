package com.github.rmannibucau.letsencrypt.manager;

import static java.util.Arrays.asList;
import static java.util.Locale.ENGLISH;
import static java.util.Optional.ofNullable;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.security.KeyPair;
import java.util.Collection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

@WebListener
public class LetsEncryptManager implements ServletContextListener {

    private Runnable shutdown;

    @Override
    public void contextInitialized(final ServletContextEvent sce) {
        // final String challengeType = "http"; // hardcoded
        final File userKey = new File(System.getProperty("letsencrypt.user_key",
                new File(System.getProperty("catalina.base"), "conf/letsencrypt_user.key").getAbsolutePath()));
        final File domainKey = new File(System.getProperty("letsencrypt.domain_key",
                new File(System.getProperty("catalina.base"), "conf/letsencrypt_domain.key").getAbsolutePath()));
        final File domainCsr = new File(System.getProperty("letsencrypt.domain_csr",
                new File(System.getProperty("catalina.base"), "conf/letsencrypt_domain.csr").getAbsolutePath()));
        final File domainChain = new File(System.getProperty("letsencrypt.domain_chain",
                new File(System.getProperty("catalina.base"), "conf/letsencrypt_domain_chain.crt").getAbsolutePath()));
        final int keySize = Integer.getInteger("letsencrypt.key_size", 2048);
        final Collection<String> domains = asList(
                System.getProperty("letsencrypt.domains", sce.getServletContext().getServletContextName()).split(","));
        final String restartBehavior = System.getProperty("letsencrypt.restart", "tomcat-reload");
        final String restartJmxName = System.getProperty("letsencrypt.restart.jmx.name", "Tomcat:name=\"http-nio-8080\",type=ThreadPool");
        final long delay = Long.getLong("letsencrypt.delay", TimeUnit.MINUTES.toMillis(5));

        sce.getServletContext().log("Starting Let's Encrypt updater with configuration:\n" +
                "    user key file: " + userKey.getAbsolutePath() + "\n" +
                "  domain key file: " + domainKey.getAbsolutePath() + "\n" +
                "domain chain file: " + domainChain.getAbsolutePath() + "\n" +
                "         key size: " + keySize + "\n" +
                "          domains: " + domains + "\n" +
                " restart behavior: " + restartBehavior + "\n" +
                "     update delay: " + delay + "\n");

        final Runnable restart;
        switch (restartBehavior.toLowerCase(ENGLISH)) {
            case "noop":
                restart = () -> sce.getServletContext().log("Updated Let's Encrypt certificate, you need to reload the certificate");
                break;
            case "jmx":
                // for meecrowave, ensure to run with --tomcat-skip-jmx=false
                restart = () -> {
                    try {
                        final ObjectName name = new ObjectName(restartJmxName);
                        final MBeanServer server = ManagementFactory.getPlatformMBeanServer();
                        if (!server.isRegistered(name)) {
                            throw new IllegalArgumentException("No MBean " + name);
                        }
                        server.invoke(name, "reloadSslHostConfigs", new Object[0], new String[0]);
                    } catch (final MalformedObjectNameException | ReflectionException | InstanceNotFoundException | MBeanException e) {
                        throw new IllegalArgumentException(e);
                    }
                };
                break;
            case "exit":
            default:
                restart = () -> System.exit(0);
        }

        final Runnable update = () -> {
            try {
                final KeyPair userKeyPair = loadOrCreateKeyPair(keySize, userKey);
                final Session session = new Session("acme://letsencrypt.org/staging"); // todo: config
                final Account account = new AccountBuilder().agreeToTermsOfService().useKeyPair(userKeyPair).create(session);

                final KeyPair domainKeyPair = loadOrCreateKeyPair(keySize, domainKey);
                final Order order = account.newOrder().domains(domains).create();
                final boolean updated = order.getAuthorizations().stream().map(authorization -> {
                    try {
                        return authorize(authorization);
                    } catch (final AcmeException | IOException e) {
                        sce.getServletContext().log(e.getMessage(), e);
                        return false;
                    }
                }).reduce(false, (previous, val) -> previous || val);
                if (!updated) {
                    return;
                }

                final CSRBuilder csrb = new CSRBuilder();
                csrb.addDomains(domains);
                csrb.sign(domainKeyPair);

                try (final FileWriter fw = new FileWriter(domainCsr)) {
                    csrb.write(fw);
                }

                order.execute(csrb.getEncoded());

                try {
                    int attempts = 20; // todo: config
                    while (order.getStatus() != Status.VALID && attempts-- > 0) {
                        if (order.getStatus() == Status.INVALID) {
                            throw new AcmeException("Order failed... Giving up.");
                        }
                        Thread.sleep(3000L); // todo: config
                        order.update();
                    }
                } catch (InterruptedException ex) {
                    sce.getServletContext().log("let's encrypt refresh interrupted", ex);
                    Thread.currentThread().interrupt();
                }

                final Certificate certificate = order.getCertificate();
                sce.getServletContext().log("Got new certificate: " + certificate.getLocation() + " for " + domains);

                // Write a combined file containing the certificate and chain.
                try (FileWriter fw = new FileWriter(domainChain)) {
                    certificate.writeCertificate(fw);
                }
            } catch (final IOException | AcmeException ioe) {
                sce.getServletContext().log(ioe.getMessage(), ioe);
            }

            restart.run();
        };

        final ScheduledExecutorService pool = Executors.newScheduledThreadPool(1, r -> {
            final Thread thread = new Thread(r, "letsencrypt-" + sce.getServletContext().getServletContextName() + "-"
                    + sce.getServletContext().getContextPath().replace("/", ""));
            if (!thread.isDaemon()) {
                thread.setDaemon(true);
            }
            if (thread.getPriority() != Thread.NORM_PRIORITY) {
                thread.setPriority(Thread.NORM_PRIORITY);
            }
            return thread;
        });
        final ScheduledFuture<?> updateFuture = pool.scheduleWithFixedDelay(update, delay, delay, MILLISECONDS);

        shutdown = () -> {
            try {
                updateFuture.cancel(true);
            } finally {
                pool.shutdown();
            }
        };
    }

    @Override
    public void contextDestroyed(final ServletContextEvent sce) {
        ofNullable(shutdown).ifPresent(Runnable::run);
    }

    private KeyPair loadOrCreateKeyPair(final int keySize, final File file) throws IOException {
        if (file.exists()) {
            try (final FileReader fr = new FileReader(file)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(keySize);
            try (FileWriter fw = new FileWriter(file)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }

    private boolean authorize(final Authorization authorization) throws AcmeException, IOException {
        final Challenge challenge = httpChallenge(authorization);
        if (challenge == null) {
            throw new AcmeException("No HTTP challenge found");
        }
        if (challenge.getStatus() == Status.VALID) {
            return false;
        }

        challenge.trigger();

        try {
            int attempts = 20; // todo: config
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                Thread.sleep(3000L); // todo: config
                challenge.update();
            }
        } catch (final InterruptedException ex) {
            Thread.currentThread().interrupt();
        }

        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain " + authorization.getDomain() + ", ... Giving up.");
        }
        return true;
    }

    private Challenge httpChallenge(final Authorization auth) throws AcmeException, IOException {
        final Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // todo: use a valve?
        final File target = new File(System.getProperty("catalina.base"),
                "webapps/.well-known/acme-challenge/" + challenge.getToken());
        target.getParentFile().mkdirs();
        try (final Writer writer = new FileWriter(target)) {
            writer.write(challenge.getAuthorization());
        }

        return challenge;
    }
}
