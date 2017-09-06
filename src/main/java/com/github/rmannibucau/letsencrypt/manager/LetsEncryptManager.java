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
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.management.ObjectName;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
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
        final String restartBehavior = System.getProperty("letsencrypt.restart", "noop");
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
        case "restart":
            // idea is to grab system properties catalina.base/home and relaunch the process after having shut down current one
            throw new UnsupportedOperationException("Auto restart not yet implemented");
        case "jmx":
            throw new UnsupportedOperationException("Tomcat doesn't support yet certificate reloading of certificates");
        case "exit":
        default:
            restart = () -> System.exit(0);
        }

        final Runnable update = () -> {
            try {
                final KeyPair userKeyPair = loadOrCreateKeyPair(keySize, userKey);
                final Session session = new Session("acme://letsencrypt.org/staging", userKeyPair);
                final Registration reg = findOrRegisterAccount(session);
                final boolean updated = domains.stream().map(d -> {
                    try {
                        return authorize(reg, d);
                    } catch (final IOException | AcmeException e) {
                        throw new IllegalStateException(e);
                    }
                }).reduce(false, (previous, val) -> previous || val);
                if (!updated) {
                    return;
                }

                final KeyPair domainKeyPair = loadOrCreateKeyPair(keySize, domainKey);
                final CSRBuilder csrb = new CSRBuilder();
                csrb.addDomains(domains);

                csrb.sign(domainKeyPair);
                try (final Writer out = new FileWriter(domainCsr)) {
                    csrb.write(out);
                }

                final Certificate certificate = reg.requestCertificate(csrb.getEncoded());
                final X509Certificate cert = certificate.download();
                final X509Certificate[] chain = certificate.downloadChain();

                try (final FileWriter fw = new FileWriter(domainChain)) {
                    CertificateUtils.writeX509CertificateChain(fw, cert, chain);
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

    private Registration findOrRegisterAccount(final Session session) throws AcmeException {
        Registration reg;

        try {
            reg = new RegistrationBuilder().create(session);
            final URI agreement = reg.getAgreement();
            acceptAgreement(reg, agreement);
        } catch (final AcmeConflictException ex) {
            reg = Registration.bind(session, ex.getLocation());
        }

        return reg;
    }

    private boolean authorize(final Registration reg, final String domain) throws AcmeException, IOException {
        final Authorization auth = reg.authorizeDomain(domain);
        final Challenge challenge = httpChallenge(auth);
        if (challenge.getStatus() == Status.VALID) {
            return false;
        }

        challenge.trigger();

        try {
            int attempts = 20;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                Thread.sleep(3000L);
                challenge.update();
            }
        } catch (final InterruptedException ex) {
            Thread.currentThread().interrupt();
        }

        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain " + domain + ", ... Giving up.");
        }
        return true;
    }

    private Challenge httpChallenge(final Authorization auth) throws AcmeException, IOException {
        final Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        final File target = new File(System.getProperty("catalina.base"),
                "webapps/.well-known/acme-challenge/" + challenge.getToken());
        target.getParentFile().mkdirs();
        try (final Writer writer = new FileWriter(target)) {
            writer.write(challenge.getAuthorization());
        }

        return challenge;
    }

    private void acceptAgreement(final Registration reg, final URI agreement) throws AcmeException {
        reg.modify().setAgreement(agreement).commit();
    }
}
