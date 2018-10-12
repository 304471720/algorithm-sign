/** Questa classe contiene i metodi necessari per:
 *    1) generare la chiave privata;
 *    2) generare la chiave pubblica;
 *    3) generare la Shared secret.
 */
package com.lhx.asymmetryencrypt.ecdh.Cryptography;

import com.lhx.asymmetryencrypt.ecdh.Curve.Curva;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Random;

/**
 *
 * @author Bigfa
 */
public class ECDH {

    private Curva curve; //curva sulla quale effettuare le operazioni.

    public ECDH() {}
    
    public void setCurva(Curva c){
        this.curve=c;
    }

    /**
     * La chiave privata è generata come numero random compreso nell'intervallo
     * {1,...,n-1} dove n è l'ordine del sottogruppo costituito dai multipli del
     * generatore G.
     */
    public BigInteger GeneratePrivateKey() {
        Random rnd = new Random();
        BigInteger n = this.curve.getN();
        int bitlength = (n.toString(2)).length();
        BigInteger d;
        do {
            d = new BigInteger(bitlength, rnd);
        } while (d.compareTo(n) >= 0 || d.compareTo(BigInteger.ZERO) == 0);
        return d;
    }

    /**
     * La chiave pubblica è generata attraverso la moltiplicazione scalare tra
     * la chiave privata e il generatore G della curva. N.B. la moltiplicazione
     * scalare può essere eseguita sia con Double&Add che con MontgomeryLadder
     * --> si preferisce il secondo algoritmo perché garantisce la resistenza ad
     * attacchi di tipo "side-channel".
     */
    public ECPoint GeneratePublicKey(BigInteger d) throws Curva.IsntOnTheCurveException {
        ECPoint P = this.curve.MontgomeryLadder(d, this.curve.getG());
        return P;
    }

    /**
     * La Shared Secret o chiave di sessione è generata come moltiplicazione
     * scalare tra la chiave privata dell'utente A e la chiave pubblica
     * dell'utente B.
     */
    public ECPoint GenerateSharedSecret(BigInteger d, ECPoint OtherPubKey) throws Curva.IsntOnTheCurveException {
        ECPoint S = this.curve.MontgomeryLadder(d, OtherPubKey);
        return S;
    }
    
    /**Funzione che verifica che la chiave pubblica generata abbia determinate 
     * caratteristiche aritmetiche. 
     * 
     * N.B. Il fatto che la funzione restituisca "true" garantisce l'esistenza 
     * di una chiave privata associata (ma non che effettivamente la controparte
     * l'abbia calcolata). La validazione della chiave pubblica altrui è 
     * fondamentale in protocolli di key-establishment basati su DH dove la 
     * Shared secret è derivata combinando la propria chiave privata con quella 
     * pubblica della controparte.Infatti, una controparte disonesta potrebbe 
     * inviare una chiave pubblica "non valida" che in qualche modo, attraverso, 
     * la shared secret potrebbe rivelare informazioni sulla nostra chiave 
     * privata.
     * 
     * @param pubkey chiave pubblica da verificare
     * @return boolean 
     */
    
    public boolean PublicKeyValidation(ECPoint pubkey){
        BigInteger x=pubkey.getAffineX();
        BigInteger y=pubkey.getAffineY();
        BigInteger p=this.curve.getP();
        if(pubkey==ECPoint.POINT_INFINITY){ //si verifica che la chiave pubblica sia diversa dal punto all'infinito 
            return false;
        }
        else if(!((x.compareTo(BigInteger.valueOf(-1))==1)&& // si verifica che le coordinate x e y della chiave pubblica appartengano al campo finito Fp
                (y.compareTo(BigInteger.valueOf(-1))==1) &&
                (x.compareTo(p)==-1) &&
                (y.compareTo(p)==-1))){
                    return false;
                }
        else if (!curve.IsOnTheCurve(pubkey)){ // si verifica che la chiave pubblica appartenga alla curva
            return false;
        }
        else return true;
    }
}
