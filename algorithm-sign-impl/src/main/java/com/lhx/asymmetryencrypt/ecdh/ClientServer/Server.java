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
import java.net.ServerSocket;
import java.security.spec.ECPoint;
import java.io.IOException;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server implements Runnable {

    private Socket socket;
    private ECPoint ServerPublicKey;
    private BigInteger ServerPrivateKey;

    public Server(Socket s) {
        this.socket = s;
    }
    
    public void setPrivateKey(BigInteger d){
        this.ServerPrivateKey=d;
    }
    
    public void setPublicKey(ECPoint p){
        this.ServerPublicKey=p;
    }

    public void run() {
        try {
            Curva c = new Curva("NIST", 128); // viene creata una nuova curva
            ECDH e = new ECDH();
            e.setCurva(c);
            this.ServerPrivateKey = e.GeneratePrivateKey(); //viene generata la chiave privata
            this.ServerPublicKey = e.GeneratePublicKey(this.ServerPrivateKey); //viene generata la chiave pubblica
            DataOutputStream out = new DataOutputStream(this.socket.getOutputStream());
            DataInputStream in = new DataInputStream(this.socket.getInputStream());
            byte[] Xbytes = this.ServerPublicKey.getAffineX().toByteArray(); //la coordinata X della chiave pubblica viene tradotta in un array di byte
            byte[] Ybytes = this.ServerPublicKey.getAffineY().toByteArray(); //la coordinata Y della chiave pubblica viene tradotta in un array di byte
            int length = Xbytes.length + Ybytes.length; //somma della lunghezza dei due array
            out.writeInt(length); // la lunghezza viene inviata al client
            out.writeInt(Xbytes.length); // la lunghezza viene dell'array di byte della coordinata X viene inviata al client 
            // --> in questo modo sottraendo alla lunghezza totale quella della X il client p in grado 
            //di determinare la lunghezza della Y
            byte[] XYbytes = new byte[length]; // vengono concatenati i due array 
            System.arraycopy(Xbytes, 0, XYbytes, 0, Xbytes.length);
            System.arraycopy(Ybytes, 0, XYbytes, Xbytes.length, Ybytes.length);
            out.write(XYbytes); // l'array risultante viene inviato al client
            int othlength = in.readInt(); // si legge la lunghezza dell'array inviato dal client
            int othXlength = in.readInt(); // si legge la lunghezza dell'array di byte della X inviato dal client
            byte[] othXYbytes = new byte[othlength];
            byte[] othXbytes = new byte[othXlength];
            byte[] othYbytes = new byte[othlength - othXlength];
            in.readFully(othXYbytes); // si legge l'array XY inviato dal server
            System.arraycopy(othXYbytes, 0, othXbytes, 0, othXlength); // si scompone nei due array othXbytes
            System.arraycopy(othXYbytes, othXlength, othYbytes, 0, othYbytes.length); // e othYbytes
            ECPoint ClientPublicKey = new ECPoint(new BigInteger(othXbytes), new BigInteger(othYbytes)); // a questo punto è possibile ottenere la chiave pubblica del client
            if (e.PublicKeyValidation(ClientPublicKey)) { //viene verificata la validità della chiave pubblica ricevuta dal client
                System.out.println("Private Key: " + this.ServerPrivateKey);
                System.out.println("Public Key:");
                System.out.println("X: " + this.ServerPublicKey.getAffineX());
                System.out.println("Y: " + this.ServerPublicKey.getAffineY());
                System.out.println("Client Public key:");
                System.out.println("X: " + ClientPublicKey.getAffineX());
                System.out.println("Y: " + ClientPublicKey.getAffineY());
                ECPoint SharedSecret = e.GenerateSharedSecret(this.ServerPrivateKey, ClientPublicKey);
                System.out.println("Shared Secret:");
                System.out.println("X: " + SharedSecret.getAffineX());
                System.out.println("Y: " + SharedSecret.getAffineY());
            } else {
                System.out.println("La chiave pubblica ricevuta è invalida!");
            }
        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Curva.IsntOnTheCurveException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Server avviato! In attesa di client!");
        ServerSocket ss = new ServerSocket(6789); // viene avviato il server sulla porta indicata
        while (true) { // viene fatto ciclare all'infinito
            Socket s = ss.accept(); // il server viene posto in attesa della connessione di un client
            System.out.println("Client connesso!");
            Server slave = new Server(s);
            Thread t = new Thread(slave); //alla connessione di un client si crea un nuovo thread
            t.start();
        }
    }

}
