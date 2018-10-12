package com.lhx.asymmetryencrypt.ecdh.Curve;

/**
 *
 * @author Bigfa
 */
import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Random;

public class Curva {

    private String Name; //nome della curva
    private int SecLevel; // livello di sicurezza
    private BigInteger a; // parametro a dell'equazione della curva
    private BigInteger b; // parametro b dell'equazione della curva
    private BigInteger p; // cardinalita' del campo Fp
    private ECPoint G; // generatore del sottogruppo
    private BigInteger n; // cardinalita' del sottogruppo
    private int h; // cofattore del sottogruppo

    /**
     *
     * @param n nome agenzia (Es. NIST, Brainpool ecc.)
     * @param sl livello di sicurezza (Es. 112, 128, 192, 256) --> poiché per la
     * crittografia simmetrica il livello di sicurezza reale è dato da n/2 per
     * garantire ad es. un livello di sicurezza pari a 112 sono necessari 224
     * bit dove n è l'ordine del sottogruppo generato da G. Il livello di
     * sicurezza è solitamente espresso in bit, dove un livello di sicurezza
     * pari a n-bit sta a significare che un "attacker" deve eseguire 2^n
     * operazioni per violarlo.
     */
    public Curva(String n, int sl) {
        if (n == "NIST") {
            if (sl == 112) {
                this.NISTP224();
            } else if (sl == 128) {
                this.NISTP256();
            } else if (sl == 192) {
                this.NISTP384();
            } else if (sl == 256) {
                this.NISTP521();
            } else {
                this.NISTP256();
            }
        } else {
            this.NISTP256();
        }
    }

    /**
     * ************************************************************SET************************************************************************
     */
    public void setName(String n) {
        this.Name = n;
    }

    public void setSecLevel(int sl) {
        this.SecLevel = sl;
    }

    public void setA(BigInteger A) {
        this.a = A;
    }

    public void setB(BigInteger B) {
        this.b = B;
    }

    public void setP(BigInteger P) {
        this.p = P;
    }

    public void setG(ECPoint ep) {
        this.G = ep;
    }

    public void setN(BigInteger N) {
        this.n = N;
    }

    public void setH(int H) {
        this.h = H;
    }

    /**
     * ****************************************************************GET*********************************************************************
     */
    public String getName() {
        return this.Name;
    }

    public int getSecLevel() {
        return this.SecLevel;
    }

    public BigInteger getA() {
        return new BigInteger(this.a.toString());
    }

    public BigInteger getB() {
        return new BigInteger(this.b.toString());
    }

    public BigInteger getP() {
        return new BigInteger(this.p.toString());
    }

    public ECPoint getG() {
        return new ECPoint(this.G.getAffineX(),this.G.getAffineY());
    }

    public BigInteger getN() {
        return new BigInteger(this.n.toString());
    }

    public int getH() {
        return this.h;
    }

    /**
     * ******************************************************************CURVE******************************************************************
     */
    public void NISTP224() {
        this.setName("NIST P224");
        this.setSecLevel(112);
        this.setA(BigInteger.valueOf(-3)); //--> il coefficiente a è posto -3 per motivi di efficienza (IEEE P1363)
        this.setB(new BigInteger("18958286285566608000408668544493926415504680968679321075787234672564"));
        BigInteger Xg = new BigInteger("19277929113566293071110308034699488026831934219452440156649784352033");
        BigInteger Yg = new BigInteger("19926808758034470970197974370888749184205991990603949537637343198772");
        this.setG(new ECPoint(Xg, Yg));
        this.setP(new BigInteger("26959946667150639794667015087019630673557916260026308143510066298881"));
        this.setN(new BigInteger("26959946667150639794667015087019625940457807714424391721682722368061"));
        this.setH(1); // il cofattore posto a 1 fa si che chiave privata e chiave pubblica abbiano approssimativamente la stessa lunghezza
    }

    public void NISTP256() {
        this.setName("NIST P256");
        this.setSecLevel(128);
        this.setA(BigInteger.valueOf(-3));
        this.setB(new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
        BigInteger Xg = new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286");
        BigInteger Yg = new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109");
        this.setG(new ECPoint(Xg, Yg));
        this.setP(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"));
        this.setN(new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"));
        this.setH(1);
    }

    public void NISTP384() {
        this.setName("NIST P384");
        this.setSecLevel(192);
        this.setA(BigInteger.valueOf(-3));
        this.setB(new BigInteger("27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575"));
        BigInteger Xg = new BigInteger("26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087");
        BigInteger Yg = new BigInteger("8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871");
        this.setG(new ECPoint(Xg, Yg));
        this.setP(new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"));
        this.setN(new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"));
        this.setH(1);
    }

    public void NISTP521() {
        this.setName("NIST P521");
        this.setSecLevel(256);
        this.setA(BigInteger.valueOf(-3));
        this.setB(new BigInteger("1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984"));
        BigInteger Xg = new BigInteger("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846");
        BigInteger Yg = new BigInteger("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784");
        this.setG(new ECPoint(Xg, Yg));
        this.setP(new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"));
        this.setN(new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"));
        this.setH(1);
    }

    /** Funzione che verifica se il punto A è sulla curva
     * 
     * @param A
     * @return Boolean
     */
    public Boolean IsOnTheCurve(ECPoint A) {
        if (A.equals(ECPoint.POINT_INFINITY)) { // se A è il punto all'infinito appartiene sicuramente alla curva per sua stessa definizione
            return true;
        } else {
            BigInteger x = A.getAffineX();
            BigInteger y = A.getAffineY(); //ricorda: y^2=x^3+ax+b (mod p) --> Eq. Weierstrass curva ellittica
            BigInteger leftmember = (y.pow(2)).mod(this.p); //y^2 (mod p)
            BigInteger rightmember = (((x.pow(3)).add((this.a).multiply(x))).add(this.b)).mod(this.p); //x^3+ax+b (mod p)
            if (leftmember.equals(rightmember)) {  //si verifica l'eguaglianza tra membro destro e membro sinistro dell'equazione
                return true;
            } else {
                return false;
            }
        }
    }

    public class IsntOnTheCurveException extends Exception {

        public IsntOnTheCurveException() {
        }

        public IsntOnTheCurveException(String message) {
            super(message);
        }
    }

    /**
     * Funzione che effettua la Point Add di due punti A e B
     *
     * @param A
     * @param B
     * @return
     * @throws
     */
    public ECPoint PointAdd(ECPoint A, ECPoint B) throws IsntOnTheCurveException {
        BigInteger Xc; // coordinata x del punto risultante dalla somma di A e B
        BigInteger Yc; // coordinata y del punto risultante dalla somma di A e B
        BigInteger Xa = A.getAffineX(); // coordinata x del punto A
        BigInteger Ya = A.getAffineY(); // coordinata y del punto A
        BigInteger Xb = B.getAffineX(); // coordinata x del punto B
        BigInteger Yb = B.getAffineY(); // coordinata y del punto B
        BigInteger m;
        try {
            if (this.IsOnTheCurve(A) && this.IsOnTheCurve(B)) {
                if (A.equals(ECPoint.POINT_INFINITY)) { // Verifico se A è il punto all'infinito 
                    return B; // in tal caso B+0=B
                } else if (B.equals(ECPoint.POINT_INFINITY)) { // Verifico se B è il punto all'infinito
                    return A; // in tal caso A+0=A
                } else if (((Xa.mod(this.p)).equals(Xb.mod(this.p)))
                        && ((((Ya.negate())).mod(this.p)).equals(Yb.mod(this.p)))) { // Verifico A e B sono simmetrici
                    return ECPoint.POINT_INFINITY; // in tal caso A+(-A)=0
                } else if (A.equals(B)) { // Verifico se i due punti sono uguali
                    // in tal caso il coefficiente angolare m è dato da m=((3Xp^2+a)/(2Yp))(mod p) 
                    // -> Point Double
                    m = (((BigInteger.valueOf(3).multiply(Xa.pow(2))).add(this.a))
                            .multiply((BigInteger.valueOf(2).multiply(Ya)).modInverse(this.p))).mod(this.p);
                    Xc = (m.pow(2).subtract(Xa.add(Xa))).mod(this.p);
                    Yc = (((Xa.subtract(Xc)).multiply(m)).subtract(Ya)).mod(this.p);
                    return new ECPoint(Xc, Yc);
                } else { // ci troviamo nel caso P!=Q
                    // in tal caso il coefficiente angola m è dato da m=((Ya-Yb)/(Xa-Xb))(mod p)
                    m = ((Ya.subtract(Yb)).multiply((Xa.subtract(Xb)).modInverse(this.p))).mod(this.p);
                    Xc = (((m.pow(2)).subtract(Xa)).subtract(Xb)).mod(this.p);
                    Yc = (((Xa.subtract(Xc)).multiply(m)).subtract(Ya)).mod(this.p);
                    return new ECPoint(Xc, Yc);
                }
            } else {
                throw new IsntOnTheCurveException("Uno o entrambi i punti non sono sulla curva");
            }
        } catch (IsntOnTheCurveException ex) {
            System.out.println(ex);
            return null;
        }
    }

    // Funzione che realizza la moltiplicazione scalare mediante l'algoritmo Double
    // & Add
    public ECPoint DoubleAndAdd(BigInteger n, ECPoint P) throws IsntOnTheCurveException {
        try {
            String nbinary = n.toString(2); // traduco lo scalare in una stringa binaria
            ECPoint result = P;
            for (int i = 1; i < (nbinary.length()); i++) { // a partire dalla seconda cifra binaria più significativa
                // fino alla meno significativa
                result = this.PointAdd(result, result); // faccio una Point Double
                if (nbinary.charAt(i) == '1') // e se la cifra binaria i-esima è uguale a 1
                {
                    result = this.PointAdd(result, P); // faccio una Point Add
                }
            }
            return result;
        } catch (IsntOnTheCurveException ex) {
            System.out.println(ex);
            return null;
        }
    }

    // Funzione che realizza la moltiplicazione scalare mediante l'algoritmo
    // Montgomery Ladder
    public ECPoint MontgomeryLadder(BigInteger n, ECPoint P) throws IsntOnTheCurveException {
        try {
            ECPoint P1 = P; // si pone P1=P
            ECPoint P2 = this.PointAdd(P, P); // e P2=2P
            String nbinary = n.toString(2); // traduco lo scalare in una stringa binaria
            for (int i = 1; i < (nbinary.length()); i++) { // a partire dalla seconda cifra più significativa fino alla
                // cifra meno significativa
                if (nbinary.charAt(i) == '1') { // se la cifra binaria i-esima è uguale a 1
                    P1 = this.PointAdd(P1, P2); // P1=P1+P2
                    P2 = this.PointAdd(P2, P2); // P2=2P2
                } else { // se la cifra binaria i-esima è uguale a 0
                    P2 = this.PointAdd(P1, P2); // P2=P1+P2
                    P1 = this.PointAdd(P1, P1); // P1=2P1
                }
            }
            return P1; // P1 è il risultato
        } catch (IsntOnTheCurveException ex) {
            System.out.println(ex);
            return null;
        }
    }
}
