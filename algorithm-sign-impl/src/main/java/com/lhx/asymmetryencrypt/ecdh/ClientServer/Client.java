package com.lhx.asymmetryencrypt.ecdh.ClientServer;

/**
 *
 * @author Bigfa
 */
import com.lhx.asymmetryencrypt.ecdh.Cryptography.ECDH;
import com.lhx.asymmetryencrypt.ecdh.Curve.Curva;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.spec.ECPoint;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private Socket socket;
    private int port; //numero di porta del server
    private String ipserver; //indirizzo ip del server
    private BigInteger ClientPrivateKey; //chiave privata del client
    private ECPoint ClientPublicKey; //chiave pubblica del client

    public Client(String ip, int p) {
        this.port = p;
        this.ipserver=ip;
    }
    
    public void setPrivateKey(BigInteger d){
        this.ClientPrivateKey=d;
    }
    
    public void setPublicKey(ECPoint p){
        this.ClientPublicKey=p;
    }
    /**
     * Funzione che provvede all'instaurazione della connessione con il server
     */
    public void Connect() throws UnknownHostException {
        try {
            System.out.println("Connessione al server in corso...");
            this.socket = new Socket(this.ipserver, this.port);
            System.out.println("Connessione avvenuta!");
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Funzione che provvede a: 1) inviare la chiave pubblica del client al
     * server; 2) ricevere la chiave pubblica del server.
     */
    public ECPoint Exchange() {
        try {
            DataInputStream in = new DataInputStream(this.socket.getInputStream());
            DataOutputStream out = new DataOutputStream(this.socket.getOutputStream());
            byte[] Xbytes = this.ClientPublicKey.getAffineX().toByteArray(); //la coordinata X della chiave pubblica viene tradotta in un array di byte
            byte[] Ybytes = this.ClientPublicKey.getAffineY().toByteArray(); //la coordinata Y della chiave pubblica viene tradotta in un array di byte
            int length = Xbytes.length + Ybytes.length; //somma della lunghezza dei due array
            out.writeInt(length); // la lunghezza viene inviata al server
            out.writeInt(Xbytes.length); // la lunghezza dell'array di byte della coordinata X viene inviata al server 
            // --> in questo modo sottraendo alla lunghezza totale quella della X il server è in grado 
            //di determinare la lunghezza della Y
            byte[] XYbytes = new byte[length]; // vengono concatenati i due array 
            System.arraycopy(Xbytes, 0, XYbytes, 0, Xbytes.length);
            System.arraycopy(Ybytes, 0, XYbytes, Xbytes.length, Ybytes.length);
            out.write(XYbytes); // l'array risultante viene inviato al server
            int othlength = in.readInt(); // si legge la lunghezza dell'array inviato dal server
            int othXlength = in.readInt(); // si legge la lunghezza dell'array di byte della X inviato dal server
            byte[] othXYbytes = new byte[othlength];
            byte[] othXbytes = new byte[othXlength];
            byte[] othYbytes = new byte[othlength - othXlength];
            in.readFully(othXYbytes); // si legge l'array XY inviato dal server
            System.arraycopy(othXYbytes, 0, othXbytes, 0, othXlength); // si scompone nei due array othXbytes
            System.arraycopy(othXYbytes, othXlength, othYbytes, 0, othYbytes.length);// e othYbytes
            ECPoint ServerPublicKey = new ECPoint(new BigInteger(othXbytes), new BigInteger(othYbytes)); // a questo punto è possibile ottenere la chiave pubblica del server
            return ServerPublicKey;
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        Curva c = new Curva("NIST", 128);
        // viene creata una nuova curva
        ECDH e = new ECDH();
        e.setCurva(c);
        Client cl = new Client("127.0.0.1", 6789); // viene creato un nuovo client
        BigInteger d = e.GeneratePrivateKey(); //viene generata la chiave privata 
        ECPoint pubkey = e.GeneratePublicKey(d); // viene generata la chiave pubblica
        cl.setPrivateKey(d);
        cl.setPublicKey(pubkey);
        cl.Connect(); //viene effettuata la connessione al server 
        ECPoint othPublicKey = cl.Exchange(); //viene effettuato lo scambio delle chiavi pubbliche con il server 
        if (e.PublicKeyValidation(othPublicKey)) { //viene verificata la validità della chiave pubblica ricevuta dal server
            ECPoint SharedSecret = e.GenerateSharedSecret(d, othPublicKey); // viene generata la Shared Secret
            // Stampa delle chiavi 
            System.out.println("Private Key: " + d);
            System.out.println("Public Key:");
            System.out.println("X: " + pubkey.getAffineX());
            System.out.println("Y: " + pubkey.getAffineY());
            System.out.println("Server Public Key:");
            System.out.println("X: " + othPublicKey.getAffineX());
            System.out.println("Y: " + othPublicKey.getAffineY());
            System.out.println("Shared Secret:");
            System.out.println("X: " + SharedSecret.getAffineX());
            System.out.println("Y: " + SharedSecret.getAffineY());
        } else {
            System.out.println("La chiave pubblica ricevuta è invalida!");
        }
    }

}
