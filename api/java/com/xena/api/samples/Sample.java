package com.xena.api.samples;

import java.util.*;
import java.net.http.*;
import java.net.URI;
import java.io.*;
import java.nio.charset.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;

public class Sample {  
    public static void main(String args[]) throws Exception
    {
        var key = "<API key>";
        var secret = "<API secret>";
        var accountId = 0;
        var uri = String.format("https://api.demo.xena.io/trading/accounts/%d/balance", accountId);
        var nonce = System.currentTimeMillis() * 1000000;
        var payload = String.format("AUTH%d", nonce);
        var signature = XenaSignature.sign(secret, payload);
      
        var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();
        var request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(uri))
            .setHeader("X-AUTH-API-KEY", key)
            .setHeader("X-AUTH-API-PAYLOAD", payload)
            .setHeader("X-AUTH-API-SIGNATURE", signature)
            .setHeader("X-AUTH-API-NONCE", String.format("%d", nonce))
            .build();
        
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }
}

final class XenaSignature {
    public static String sign(String apiKey, String data) throws Exception {
        var keyInfo = ASN1.parseASN1String(apiKey);
        if (!ASN1.NIST_P_256_CURVE.equalsIgnoreCase(keyInfo.getCurveNameHex())) {
            throw new Exception("Curves other than NIST P256 are not supported");
        }

        var privKey = keyInfo.getPrivateKey();
        var parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        var ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        var privKeySpec = new ECPrivateKeySpec(new BigInteger(1, privKey), ecParameters);
        var kf = KeyFactory.getInstance("EC");
        var pk = kf.generatePrivate(privKeySpec);
        
        var ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(pk);
        ecdsa.update(data.getBytes(StandardCharsets.US_ASCII));
        var res = ecdsa.sign();
        
        return Utils.byteArrayToHexString(ASN1.parseSignature(res).getRS());
    }
}

final class ASN1 {
    public static ASN1ECKeyStructure parseASN1String(String input) throws Exception {            
        var bytes = Utils.getBytes(input);
        var stream = new ByteArrayInputStream(bytes);
        var res = new ASN1ECKeyStructure();

        int token;
        do
        {
            token = stream.read();
            switch (token) {
                case 0x30: continue;    // sequence opening tag
                case 0x77: res.setVersion(readToken(stream)); break;
                case 0x04: res.setPrivateKey(readToken(stream)); break;
                case 0xA0:
                    {
                        var content = readToken(stream);
                        var contentStream = new ByteArrayInputStream(content);
                        if (contentStream.read() == 0x06)
                        {
                            res.setCurveName(readToken(contentStream));
                        }
                    }
                    break;
                case 0xA1:
                    {
                        var content = readToken(stream);
                        var contentStream = new ByteArrayInputStream(content);
                        if (contentStream.read() == 0x03)
                        {
                            var child = readToken(contentStream);
                            var childStream = new ByteArrayInputStream(child);
                            if (childStream.read() == 0x00 && childStream.read() == 0x04)
                            {
                                var pubkey = new byte[childStream.available() - 2];
                                childStream.read(pubkey, 0, pubkey.length);
                                res.setPublicKey(pubkey);
                            }
                        }
                    }
                    break;
            }
        }
        while (token != -1);

        return res;
    }

    public static ASN1SignatureStructure parseSignature(byte[] input) {
        var stream = new ByteArrayInputStream(input);
        var res = new ASN1SignatureStructure();

        int token;
        int position = 0;

        do
        {
            token = stream.read();
            
            // skip the sequence opening tag
            if (token == 0x30 && position == 0) {
                position = 1;
                continue;
            }
            // skip 1 or 2 bytes denoting the content length (until there is 0x02 denoting INT)
            if (position == 1 && token != 0x02) {
                continue;
            }

            if (token == 0x02) {
                position++;
                var val = readToken(stream);
                switch (position) {
                    case 2: res.setR(val); break;
                    case 3: res.setS(val); break;
                }
            }
        }
        while (token != -1);

        return res;
    }

    public static String NIST_P_256_CURVE = "2A8648CE3D030107";

    static byte[] readToken(ByteArrayInputStream stream) {
        var contentLength = stream.read();
        var res = new byte[contentLength];
        for (var i = 0; i < contentLength; i++)
        {
            res[i] = (byte)stream.read();
        }
        return res;
    }
}

final class Utils {
    public static byte[] getBytes(String hex) {
        var len = hex.length();
        var res = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            res[i / 2] = (byte)(
                (Character.digit(hex.charAt(i), 16) << 4) 
                + Character.digit(hex.charAt(i + 1), 16)
            );
        }
        return res;
    }

    public static String byteArrayToHexString(byte[] ba) {
        StringBuilder sb = new StringBuilder(ba.length * 2);
        for(byte b: ba) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString().toUpperCase();
    }

    public static byte[] reverseByteArray(byte[] ba) {
        var res = new byte[ba.length];
        for (var i = 0; i < ba.length; i++) {
            res[i] = ba[ba.length - i - 1];
        }
        return res;
    }
}

final class ASN1ECKeyStructure {
    byte[] version, privateKey, curveName, publicKey, qx, qy;
    
    public byte[] getVersion() {
        return this.version;
    }
    
    public void setVersion(byte[] version) {
        this.version = version;
    }
    
    public byte[] getPrivateKey() {
        return this.privateKey;
    }
    
    public void setPrivateKey(byte[] pk) {
        this.privateKey = pk;
    }
    
    public byte[] getCurveName() {
        return this.curveName;
    }
    
    public void setCurveName(byte[] curveName) {
        this.curveName = curveName;
    }
    
    public String getCurveNameHex() {
        return this.curveName != null ? Utils.byteArrayToHexString(this.curveName) : null;
    }

    public byte[] getPublicKey() {
        return this.publicKey;
    }
    
    public void setPublicKey(byte[] pk) throws Exception {
        if (pk.length % 2 != 0) throw new Exception("Public key length is not even");
        this.publicKey = pk;
        this.qx = new byte[pk.length / 2];
        System.arraycopy(pk, 0, this.qx, 0, pk.length / 2);
        this.qy = new byte[pk.length / 2];
        System.arraycopy(pk, pk.length / 2, this.qy, 0, pk.length / 2);
    }
    
    public byte[] getQx() {
        return this.qx;
    }
    
    public byte[] getQy() {
        return this.qy;
    }
}

final class ASN1SignatureStructure {
    byte[] r, s;
    
    public void setR(byte[] r) {
        // if the first byte is 0 to denote that the number is positive, this zero must be skipped
        if (r[0] != 0) {
            this.r = r;
        }
        else {
            this.r = Arrays.copyOfRange(r, 1, r.length);
        }
    }

    public byte[] getR() {
        return this.r;
    }

    public void setS(byte[] s) {
        // if the first byte is 0 to denote that the number is positive, this zero must be skipped
        if (s[0] != 0) {
            this.s = s;
        }
        else {
            this.s = Arrays.copyOfRange(s, 1, s.length);
        }
    }

    public byte[] getS() {
        return this.s;
    }

    public byte[] getRS() {
        var res = new byte[(this.r != null ? this.r.length : 0) + (this.s != null ? this.s.length : 0)];
        
        for (var i = 0; i < this.r.length; i++) res[i] = this.r[i];
        for (var i = 0; i < this.s.length; i++) res[i + this.r.length] = this.s[i];
        return res;
    }
}