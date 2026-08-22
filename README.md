# Authentifizierung über öffentliche Schlüssel mit Apache MINA

In der Fortsetzung meines Blog-Beitrags [Migration von Videomitschnitten mit Apache MINA – Teil 1](https://www.adesso.de/de/news/blog/migration-von-videomitschnitten-mit-apache-mina-teil-1.jsp) werden wir die Authentifizierung über öffentliche Schlüssel mit dem Apache-MINA-Framework untersuchen.
Ich beginne mit einem Überblick über die für uns relevanten kryptographischen Verfahren und Methoden. 
Anschließend schauen wir uns die Implementierung der Authentifizierung über öffentliche Schlüssel in einem Prototyp und einem vom Framework abgeleiteten Konzept für die Authentifizierung an.

## Asymmetrische Verschlüsselung
Bei der asymmetrischen Verschlüsselung werden zwei sich ergänzende Schlüssel verwendet: der private und der öffentliche Schlüssel.
Mit dem privaten Schlüssel werden Nachrichten entschlüsselt und digitale Signaturen erzeugt.
Mit dem öffentlichen Schlüssel werden Nachrichten verschlüsselt und digitale Signaturen auf ihre Authentizität überprüft.
Wie der Name schon sagt, kann der öffentliche Schlüssel öffentlich zugänglich gemacht werden. 
Jeder kann mit dem öffentlichen Schlüssel Nachrichten verschlüsseln, da diese nur mit dem privaten Schlüssel entschlüsselt werden können. 
Maßgeblich ist hierbei, dass der private Schlüssel nicht aus dem öffentlichen Schlüssel berechnet werden kann.

## Digitale Signatur
Die digitale Signatur kann verwendet werden, um Dokumente digital zu unterzeichnen sowie die Identität des Unterzeichners und die Integrität von Nachrichten zu bestätigen. 
(Rechtlich einer handschriftlichen Unterschrift gleichgestellt ist nur die qualifizierte elektronische Signatur nach eIDAS, nicht jede digitale Signatur.)
Betrachtet man einen konkreten Anwendungsfall, so erstellt der Unterzeichner zunächst eine Nachricht und berechnet daraus einen Hashwert. 
Das Hashing wandelt eine Nachricht beliebiger Länge in einen Hashwert mit fester Länge um. 
Es ist praktisch nicht möglich, aus dem Hashwert die ursprüngliche Nachricht zu berechnen. 
Der Unterzeichner signiert den von ihm erstellten Hashwert mit seinem privaten Schlüssel (was eine digitale Signatur der Nachricht darstellt) und schickt die Nachricht samt Signatur an den Prüfer. 
Der Prüfer berechnet den Hashwert der empfangenen Nachricht und prüft mit dem öffentlichen Schlüssel des Unterzeichners, ob die Signatur zu diesem Hashwert passt. 
Bei RSA kann dabei der signierte Hashwert aus der Signatur zurückgewonnen und direkt verglichen werden; bei anderen Verfahren wie ECDSA oder Ed25519 liefert die Prüfung nur ein Ja oder Nein. 
Ist die Signatur gültig, sind die Integrität der Nachricht sowie die Identität des Unterzeichners bestätigt.

![Prüfung der digitalen Signatur](DigitaleSignatur.png)


## Authentifizierung über öffentliche Schlüssel
Bevor sich der Benutzer über einen öffentlichen Schlüssel am SFTP-Server authentifizieren kann, muss der öffentliche Schlüssel für den Benutzernamen auf dem SFTP-Server konfiguriert sein. 
Die Authentifizierung erfolgt dann, wie in [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) spezifiziert, über den privaten Schlüssel des Clients. 
Während des Authentifizierungsvorgangs überprüft der SFTP-Server den öffentlichen Schlüssel des Clients und die mit dem privaten Schlüssel erstellte Signatur über die Sitzungsdaten. 
Erst wenn beide gültig sind, hat sich der Client erfolgreich authentifiziert.

Da private Schlüssel zufällig erzeugt werden und sehr viel Entropie besitzen, ist es praktisch unmöglich, sie mit Brute-Force-Angriffen zu knacken. 
Aus diesem Grund ist die Authentifizierung über öffentliche Schlüssel sicherer als die Authentifizierung über Passwörter und sollte letzterer vorgezogen werden. 
Wichtig ist, dass der private Schlüssel immer geheim bleibt, denn andernfalls wäre die Sicherheit des Verfahrens nicht mehr gegeben. 
Auf dem Client sollte er deshalb zusätzlich mit einer Passphrase geschützt werden.

## Diffie-Hellman-Schlüsselaustausch
Anders als vielleicht angenommen, kommen die Schlüssel, die für die Authentifizierung verwendet werden, nicht für die Verschlüsselung der Datenübertragung zum Einsatz. 
Bevor der Authentifizierungsvorgang beginnen kann, findet zwischen dem Client und dem Server der sogenannte Diffie-Hellman-Schlüsselaustausch statt. 
Während der Prozedur generieren der Client und der Server Schlüsselteile, die, zusammengesetzt, einen symmetrischen Schlüssel für die Verschlüsselung der Kommunikation ergeben. 
Der Server signiert diesen Austausch mit seinem Host-Key und weist sich so gegenüber dem Client aus; darauf kommen wir beim Fingerprint gleich zurück. 
Erst nach abgeschlossenem Schlüsselaustausch, also über den dann verschlüsselten Kanal, kann mit dem Authentifizierungsvorgang begonnen werden.

## Prototyp
Schauen wir uns den Authentifizierungsvorgang genauer an.
Hierfür habe ich auf GitHub einen Prototyp hinterlegt. 
Ihr könnt ihn unter [MINA-sftp-pub-auth](https://github.com/IvanKablar/MINA-sftp-pub-auth) herunterladen.
Die im Repository enthaltenen Schlüssel sind reine Wegwerf-Schlüssel für den Prototyp und dürfen nirgendwo sonst verwendet werden.
Zuerst werfen wir einen Blick auf die Konfiguration des SFTP-Servers und schauen uns die Konfiguration der Schlüssel an:

```java
@Component
public class SftpServerConfig {
    private SshServer sshd;
    @Value("${hostkey}")
    private String hostKey;
    private final ResourceLoader resourceLoader;
    private final SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator;

    public SftpServerConfig(ResourceLoader resourceLoader, SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator) {
        this.resourceLoader = resourceLoader;
        this.sftpPublicKeyAuthenticator = sftpPublicKeyAuthenticator;
    }

    @PostConstruct
    public void init() throws IOException, GeneralSecurityException {
        SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder().build();
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(9922);
        sshd.setKeyPairProvider(KeyPairProvider.wrap(loadHostKey()));
        sshd.setPublickeyAuthenticator(sftpPublicKeyAuthenticator);
        sshd.setSubsystemFactories(Collections.singletonList(factory));
        sshd.start();
    }

    private Iterable<KeyPair> loadHostKey() throws IOException, GeneralSecurityException {
        Resource resource = resourceLoader.getResource(hostKey);
        try (InputStream in = resource.getInputStream()) {
            return SecurityUtils.loadKeyPairIdentities(null, NamedResource.ofName(hostKey), in, null);
        }
    }
    ...
}
```

Der SFTP-Server wird in der Methode `init` konfiguriert.
Bevor der Server gestartet werden kann, muss eine Instanz des Typs `KeyPairProvider` bekannt gemacht werden. 
Die Schlüsseldatei, die in `loadHostKey` aus dem Classpath (`hostkey=classpath:hostkey.pem` in den `application.properties`) gelesen wird, ist der Host-Key und wird für die Identifikation des Servers verwendet.
Falls Ihr den Prototyp heruntergeladen habt, ist das Erstellen der nun im Beitrag folgenden öffentlichen bzw. privaten Schlüssel optional.
Falls Ihr trotzdem Eure eigenen Schlüssel erstellen und im Prototyp konfigurieren wollt, könnt Ihr das gerne machen.
Der Host-Key kann folgendermaßen erstellt werden: 

```bash
ssh-keygen -t rsa -m PEM
```

Die Datei kopieren wir in das `resources`-Verzeichnis des Servers.
Beim Verbindungsaufbau schickt der Server dem Client seinen öffentlichen Host-Key. 
Der Client berechnet daraus den sogenannten Fingerprint, einen kodierten SHA-256-Hashwert, und vergleicht ihn mit dem Eintrag in seiner `known_hosts`-Datei. 
Der Client sollte beim Anmelden Änderungen am Fingerprint immer genau hinterfragen. 
Zwar ist es möglich, dass der Server-Admin den Host-Key und somit den Fingerprint geändert hat, aber es könnte sich auch um einen Man-in-the-Middle-Angriff handeln. 
Nach einer erfolgreichen Authentifizierung ermöglicht die Klasse `SftpSubsystemFactory` den Zugriff auf das Dateisystem des Servers. 
Die Implementierung des Interface `PublickeyAuthenticator` schauen wir uns weiter unten im Beitrag genauer an.

## Konfiguration des öffentlichen Schlüssels
Um uns am SFTP-Server authentifizieren zu können, erzeugen wir ein Schlüsselpaar, bestehend aus einem öffentlichen und einem privaten Schlüssel:

```bash
ssh-keygen -t rsa -b 4096
```

Für neue Schlüssel empfiehlt sich heute `ssh-keygen -t ed25519`; der Prototyp funktioniert mit beiden Varianten. 
Wer bei RSA bleibt, sollte wissen, dass OpenSSH ab Version 8.8 Signaturen mit `ssh-rsa` (SHA-1) nicht mehr akzeptiert; Apache MINA SSHD unterstützt die Nachfolger `rsa-sha2-256` und `rsa-sha2-512`, sodass die Anmeldung weiterhin funktioniert.

Die Datei mit dem öffentlichen Schlüssel kann in ein beliebiges Verzeichnis auf dem Server kopiert werden. 
Um die Konfiguration in unserem Beispiel einfach zu halten, habe ich die Datei ebenfalls in das `resources`-Verzeichnis kopiert. 
Aus diesem kann der Schlüssel beim Erstellen der Benutzerinformationen gelesen werden. 
In einer produktiven Anwendung würde wahrscheinlich ein anderes Konzept hinter der Schlüsselverwaltung stehen. 
Beispielsweise könnte der öffentliche Schlüssel in einem LDAP-Verzeichnis hinterlegt werden.

Aus organisatorischer Sicht kann es sinnvoll sein, dass der Client die Schlüssel selbst erzeugt. 
Die Datei mit dem öffentlichen Schlüssel sendet er über einen beliebigen, möglicherweise unsicheren Kanal an den Server-Admin, den privaten Schlüssel behält er für sich.

## Anmeldung
Als Nächstes versuchen wir, uns mit dem privaten Schlüssel am Server zu authentifizieren:

```bash
sftp -P 9922 -i /home/ivan/id_rsa ivan@localhost
``` 

Der private Schlüssel enthält die notwendigen Informationen für das Berechnen des öffentlichen Schlüssels. 
Der vom Client geschickte öffentliche Schlüssel kann nun mit dem für den Benutzer auf dem Server konfigurierten öffentlichen Schlüssel verglichen werden. 
Außerdem überprüft das Framework die mit dem privaten Schlüssel erstellte Signatur mit dem öffentlichen Schlüssel. 
Erst wenn der Vergleich der öffentlichen Schlüssel gelingt und die Signatur korrekt ist, hat sich der Client erfolgreich authentifiziert.

## Implementierung der Authentifizierung
Mit der Bereitstellung von Interfaces für die Authentifizierung durch das Framework wird bei der Entwicklung die Überprüfung von zusätzlichen Authentifizierungskriterien ermöglicht, darunter auch der Vergleich der öffentlichen Schlüssel.
In unserem Beispiel implementiert die Klasse `SftpPublicKeyAuthenticator` eine solche Schnittstelle. 
Die Authentifizierung beginnt mit der Überprüfung des Benutzernamens. 
Anschließend findet der Vergleich der öffentlichen Schlüssel statt. 

```java
@Override
public boolean authenticate(String username, PublicKey publicKey, ServerSession serverSession) throws AsyncAuthException {
    User user = userService.getUser(username);
    if (user == null) {
        log.warn("Kein Benutzer mit Namen '{}' konfiguriert", username);
        return false;
    }
    return publicKeyService.isPublicKeyValid(userService.getUserKey(user), publicKey, serverSession);
}
```

Gut zu wissen: Das Framework ruft `authenticate` pro Anmeldung zweimal auf. 
Beim ersten Mal fragt der Client gemäß RFC 4252, Abschnitt 7, nur an, ob der Schlüssel überhaupt akzeptiert würde; beim zweiten Mal folgt die eigentliche Anmeldung mit Signatur. 
Die Methode sollte daher keine Seiteneffekte haben.

Die Methode `isPublicKeyValid` der Klasse `PublicKeyService` enthält die Logik für die Validierung und den Vergleich der öffentlichen Schlüssel. 
```java
public boolean isPublicKeyValid(String serverConfPublicKey, PublicKey clientPublicKey, ServerSession serverSession) {
    PublicKey serverPublicKey = getServerPublicKey(serverConfPublicKey, serverSession);
    if (serverPublicKey == null || clientPublicKey == null) {
        return false;
    }
    return compareKeys(clientPublicKey, serverPublicKey);
}

private PublicKey getServerPublicKey(String serverConfPublicKey, ServerSession serverSession) {
    try {
        return parsePublicKey(serverConfPublicKey, serverSession);
    } catch (IOException e) {
        log.warn("Fehler beim Dekodieren des serverseitigen Public-Keys", e);
    } catch (IllegalArgumentException e) {
        log.warn("Der serverseitige Public-Key besitzt kein gültiges Format", e);
    } catch (GeneralSecurityException e) {
        log.warn("Fehler beim Generieren des serverseitigen Public-Keys", e);
    }
    return null;
}

private PublicKey parsePublicKey(String publicKey, ServerSession serverSession) throws IOException, GeneralSecurityException {
    if (publicKey == null || publicKey.isEmpty()) {
        return null;
    }
    PublicKeyEntry publicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(publicKey);
    return publicKeyEntry.resolvePublicKey(serverSession, null, PublicKeyEntryResolver.IGNORING);
}
```

Der vom Client geschickte Schlüssel liegt bereits als `PublicKey`-Objekt vor. 
Der auf dem Server konfigurierte Schlüssel wird in `parsePublicKey` aus dem `authorized_keys`-Format gelesen. 
Konnte er fehlerfrei eingelesen werden, prüft die Methode `compareKeys`, ob der auf dem Server konfigurierte öffentliche Schlüssel mit dem öffentlichen Schlüssel des Clients übereinstimmt. 
```java
private boolean compareKeys(PublicKey clientPublicKey, PublicKey serverConfigPublicKey) {
    if (!KeyUtils.compareKeys(clientPublicKey, serverConfigPublicKey)) {
        log.warn("Die Public-Keys stimmen nicht überein");
        return false;
    }
    log.info("Die Public-Keys stimmen überein");
    return true;
}
```

Stimmen die Schlüssel nicht überein, bricht die Authentifizierung an dieser Stelle ab. 
Handelt es sich um die gleichen Schlüssel, überprüft der Server anschließend die digitale Signatur, um sicherzustellen, dass der Client im Besitz des zugehörigen privaten Schlüssels ist. Ist die digitale Signatur korrekt, hat sich der Client erfolgreich authentifiziert.

Wer keine eigene Schlüsselverwaltung braucht, kann übrigens auf den im Framework enthaltenen `AuthorizedKeysAuthenticator` zurückgreifen, der die Schlüssel aus einer `authorized_keys`-Datei liest.

# Ergebnis
Mit dem Prototyp und dem Beispiel oben haben wir die Implementierung eines Konzepts für die Authentifizierung über öffentliche Schlüssel mit dem Apache-MINA-Framework untersucht. 

Mir hat es Spaß gemacht, den SFTP-Server zu entwickeln, und ich hoffe, Euch hat mein Blog-Beitrag gefallen. Bleibt gesund und bis bald.
