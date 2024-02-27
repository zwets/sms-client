package it.zwets.sms.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class TestingKeys {
    
    public static final String B64_PRIVKEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC82Qx0XTtRRLlNpZv++7lO7YIv"
            + "Iy/PrgZFfFKgLWefAo0UYhmoFVU10lGd4nluV2GRdemoIwkwR9k9yCvzvOsIdq7yVBFf2uL8Mg/k"
            + "QD+Cf8qNaAP0mu6wm9BTbnPpzRTW3b+OepND+lAYJQE9BRAgOV/aUbGx32uKKjCrk9YAFZ6xwphZ"
            + "gCyp7njEd+eBLMHlqHReZuC6RdIuvhDFdOuCl+AcbSDhjSD6DclI765i+MjlmCxe0OCzTokLW2Ku"
            + "ajnZznxPvj6toz9FHyDBvl1WiYYpvnJ3CCcxcQbK3U6i80laMdpXIn56LbiC5LrIQUiGOW0ILYFd"
            + "Yc2MU7kdfMGJAgMBAAECggEASNnqZhF5SpaabYvPrAPrrrkNGaYXUaSuoqudLFGXwc24Iv7dKuxf"
            + "3M1v0tqFQb3P08+K/ePWLZvqAF1yJyrf+Hngb3di5HmKSwP9AW6PkYY+22Ie9IO4RMU3DphzeuQ0"
            + "f9c3iH1cxkKQF2BfI+0KFYRMp+oQBLBNyhUQhYAYdBs4G8Ruh2NOQNH4WLsYMIwcz0WreG+Syei6"
            + "Mf3MbnV1Hgw8mmbBbxwL5VMhOA/trgF3clYayAtaGrsh7oqXNeK+jrKPFlK4YlssdTDB1wpp+MEI"
            + "mqjazUxnphvkm7OS/DQMSJnPGprk92bqwrXaYe+E8ruJzoEgMcrUdGKRHPaVKQKBgQD4iwNbNN8m"
            + "k7J37ltJu3qEUDXyHupczvhsaR1bF1hFVoKMfnTUZjxTMIhvWFOMDfUarkHbUs5P3Wm7VURvsxgS"
            + "eOHmQT+h62tol9VVKq1omTJ50n7B7sUt4J80GNrP6a5clEaldjJiFma7RIyClwYGG8ajgEiRtRXj"
            + "0qsAAd1pfwKBgQDCg4jCVuUiJ3yIfpcWox+vv4FDwCd8okKFeoj4d5iIPtKSJb4trjFc/gsGwTB6"
            + "uxdE81ZDx9eHmZejbehksH3pt9+BfgrJV3oDL6fQFobpPsHxRIBWiGQi6D7E6HwO5Zbl9kdQS4rL"
            + "8pJ+23hjXuuFJGSvymlF5ka0scAownAI9wKBgQCYKqP3ZztoJu0ROEFztvCfqWwdvIfIIn8+AG0U"
            + "pApLCVgMJC/rClzMod4mLXGZQcJaf22alevyQaDGLMIlkQSf6pqDmlcXD0dHVg4qgmKAs6qPoyww"
            + "F7tpByjxgHYW7P7vd2h5TRAztXtYE/Pi0AvEGaVX3OaRLskkHorLCllAiQKBgBwML2omcX/NRc3A"
            + "wzSGbQlAifkk+gyksQbiNmHtjNcIiAB+5L9dgMyx7REaRk1MMPzGQcggRtnMserk7D+om19aHiZj"
            + "8FY8AOH4uy/sL6PuYrTRddgEbrwB1Rs7krfrLykVrA7N9cOWxLz6FI/vnfJi3wniG+/yVnuzrcuy"
            + "zcjdAoGAd0XtmtashlGOgRpeqVNFXmMoi8SAFNSfJtZGn5lHW/JJFwmA7a0NgNS6WLlPoJWaXueR"
            + "/lD1eo4Zu0aBsaNtM5+wsR1+yaWizgXPAr7sRNskp9r6INM2p2bhXIZsfyY/YAuERVD2ICsvk/1H"
            + "txtQUpXXZ4iNhCxQVRGkx+Al7Y0=";

    public static final String B64_PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNkMdF07UUS5TaWb/vu5Tu2CLyMvz64G"
            + "RXxSoC1nnwKNFGIZqBVVNdJRneJ5bldhkXXpqCMJMEfZPcgr87zrCHau8lQRX9ri/DIP5EA/gn/K"
            + "jWgD9JrusJvQU25z6c0U1t2/jnqTQ/pQGCUBPQUQIDlf2lGxsd9riiowq5PWABWescKYWYAsqe54"
            + "xHfngSzB5ah0XmbgukXSLr4QxXTrgpfgHG0g4Y0g+g3JSO+uYvjI5ZgsXtDgs06JC1tirmo52c58"
            + "T74+raM/RR8gwb5dVomGKb5ydwgnMXEGyt1OovNJWjHaVyJ+ei24guS6yEFIhjltCC2BXWHNjFO5" + "HXzBiQIDAQAB";

    public static final PrivateKey PRIVKEY = PkiUtils.readPrivateKey(Base64.getDecoder().decode(B64_PRIVKEY));
    public static final PublicKey PUBKEY = PkiUtils.readPublicKey(Base64.getDecoder().decode(B64_PUBKEY));
}
