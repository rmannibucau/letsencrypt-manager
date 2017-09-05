package com.github.rmannibucau.letsencrypt.manager;

import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

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

        final Runnable update = () -> {
            try {
                final KeyPair userKeyPair = loadOrCreateKeyPair(keySize, userKey);
                final Session session = new Session("acme://letsencrypt.org/staging", userKeyPair);
                final Registration reg = findOrRegisterAccount(session);
                domains.forEach(d -> {
                    try {
                        authorize(reg, d);
                    } catch (final IOException | AcmeException e) {
                        throw new IllegalStateException(e);
                    }
                });

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

            // restart if changed
        };

        shutdown = () -> {

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

    private void authorize(final Registration reg, final String domain) throws AcmeException, IOException {
        final Authorization auth = reg.authorizeDomain(domain);
        final Challenge challenge = httpChallenge(auth);
        if (challenge.getStatus() == Status.VALID) {
            return;
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
