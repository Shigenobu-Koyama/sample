package jp.gr.java_conf.x_shigenobu;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

import net.arnx.jsonic.JSON;
import org.apache.commons.codec.binary.Base64;
import com.nimbusds.jose.jwk.RSAKey;

public class HelloAuthenticator {

	public static void main(String[] args) {
		final String challenge = "Y2xpbWIgYSBtb3VudGFpbg";
		final String pk = "{ 	\"kty\" : \"RSA\", 	\"alg\" : \"RS256\", 	\"ext\" : false, 	\"n\" : \"k-d_ZbVlAu-EBhRNlevnd0cBqJEPlhBefOMMLgHeGTS28Uev6_xHVCZ774I2XdtVF-M5En0aTdekAX82K2SVnO9TEZ4GdJFR1kW1jppLtrlUyjQqggq60OwkUxHM14XDQBhvgeW3fjpETraB-R_scyGeK7lNWMF8jW-NjvU_nljTyuHoDVnYJxPuCunlQ7uzg80iURp0jFKhw7FedPkzyQllG0HRRfzwQG1WOyECxkdPmMk7iPdF-B-Z78S9Fd8Dx2R8OZHEpFMdQ3Z3bMLG8prSbXcmBXlBtmwSLPzEEb3FuPdJQtXzVyg2i3jAR25zWA_XemXHBv7XE5Mf3JYldQ\", 	\"e\" : \"AQAB\" }";
		final String d = "ew0KCSJjaGFsbGVuZ2UiIDogIlkyeHBiV0lnWVNCdGIzVnVkR0ZwYmciLA0KCSJ1c2VyUHJvbXB0IiA6ICJIZWxsbyEiDQp9AA";
		final String s = "M-GT64y3FXoFQI8fRPq8ogckxuVYqv65R2eJEXGpbmVtm3Zn9Oa6ik4nClFMsN4h42e9bSBslMTEKW-J1oAoxF8n4JkDH82b9j4bFhhSRMHCbmE-uZm1RX8zVrGIgoWnXDy2nGQSu5xN-BhGubru1x0sXo9ZAdXKc-5hkp6SfIdXAY15o9flsag_H_CpIJ1_L1-vO5K8xhya_iOezflNlqa8-D1lI-xMJ7dOqyPwqg33ryW4l6iTtexuiYhZaGOOyJ5ZxzchjKrw9zMgQOsjbsrM7Q6bu7K7YvOoULxM5WJFdCLj0OBZznrskEHlLrSe0TSr_WrY1SkLhRaUCetKkg";
		final String a = "AQAAAAA";
		
		String v = validateSignature(pk,d,a,s,challenge) ? "verified" : "unverified";
		System.out.println(v);
	}

    private static boolean validateSignature(String pk, String clientData, String authnrData, String signature, String challenge) {
  	
		try {
	    	// Make sure the challenge in the client data 
	        // matches the expected challenge
//	    	byte[] c1 = Base64.getDecoder().decode(clientData); //JAVA8
	        byte[] c1 = Base64.decodeBase64(clientData); //JAVA7
	    	byte[] c2 = Arrays.copyOf(c1, c1.length-1);
	    	String cc = new String(c2);
	    	Map<String,Object> obj = JSON.decode(cc);
	    	if ( !challenge.equals(String.valueOf(obj.get("challenge"))) ) return false;
	    	
	        // Hash data with sha256
	    	MessageDigest digest;
			digest = MessageDigest.getInstance("SHA-256");
	    	byte[] h = digest.digest(c1);

	        // Verify signature is correct for authnrData + hash
	    	Signature sig = Signature.getInstance("SHA256withRSA");
	    	sig.initVerify(RSAKey.parse(pk).toRSAPublicKey());
	    	sig.update(Base64.decodeBase64(authnrData));
	    	sig.update(h);
	    	return sig.verify(Base64.decodeBase64(signature));	    	
	    	
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | InvalidKeySpecException | ParseException e) {
			return false;
		}
    }
}
