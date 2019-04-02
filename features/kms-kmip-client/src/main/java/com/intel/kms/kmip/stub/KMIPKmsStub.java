/**
 *Description:
 * The Stub encapsulates the whole KMIP functionality of the
 * client side. To process a request, it encodes the request, 
 * sends it to the server over the transport layer, and finally 
 * decodes and returns the response.  
 *
 * 
 * 
 */
package com.intel.kms.kmip.stub;

import java.util.ArrayList;

import com.intel.dcsg.cpg.configuration.Configuration;

import ch.ntb.inf.kmip.container.KMIPContainer;
import ch.ntb.inf.kmip.process.decoder.KMIPDecoderInterface;
import ch.ntb.inf.kmip.process.decoder.KMIPPaddingExpectedException;
import ch.ntb.inf.kmip.process.decoder.KMIPProtocolVersionException;
import ch.ntb.inf.kmip.process.decoder.KMIPUnexpectedAttributeNameException;
import ch.ntb.inf.kmip.process.decoder.KMIPUnexpectedTagException;
import ch.ntb.inf.kmip.process.decoder.KMIPUnexpectedTypeException;
import ch.ntb.inf.kmip.process.encoder.KMIPEncoderInterface;
import ch.ntb.inf.kmip.stub.KMIPStubInterface;
import ch.ntb.inf.kmip.stub.transport.KMIPStubTransportLayerInterface;
import ch.ntb.inf.kmip.test.UCStringCompare;
import ch.ntb.inf.kmip.utils.KMIPUtils;
import static com.intel.kms.kmip.client.KMIPKeyManager.DECODER;
import static com.intel.kms.kmip.client.KMIPKeyManager.ENCODER;
import static com.intel.kms.kmip.client.KMIPKeyManager.KEYSTORELOCATION;
import static com.intel.kms.kmip.client.KMIPKeyManager.KEYSTOREPW;
import static com.intel.kms.kmip.client.KMIPKeyManager.ENDPOINT;
import static com.intel.kms.kmip.client.KMIPKeyManager.TRANSPORTLAYER;
import com.intel.kms.kmip.client.exception.KMIPClientException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import org.apache.commons.codec.binary.Hex;

/**
 * 
 * The Stub encapsulates the whole KMIP functionality of the server side.
 * 
 * @author aakashmX
 */
public class KMIPKmsStub implements KMIPStubInterface {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KMIPKmsStub.class);
	private KMIPEncoderInterface encoder;
	private KMIPDecoderInterface decoder;
	private KMIPStubTransportLayerInterface transportLayer;
	private Configuration config;

	public KMIPKmsStub(Configuration config) throws KMIPClientException {
		super();

        try {
            this.encoder = (KMIPEncoderInterface) getClass(config.get(ENCODER),
                    "ch.ntb.inf.kmip.process.encoder.KMIPEncoder")
                    .newInstance();
            this.decoder = (KMIPDecoderInterface) getClass(config.get(DECODER),
                    "ch.ntb.inf.kmip.process.decoder.KMIPDecoder")
                    .newInstance();
            this.transportLayer = (KMIPStubTransportLayerInterface) getClass(
                    config.get(TRANSPORTLAYER),
                    "ch.ntb.inf.kmip.stub.transport.KMIPStubTransportLayerHTTP")
                    .newInstance();
            this.transportLayer.setTargetHostname(config.get(ENDPOINT)); //really requires an endpoint, KMIP4j just calls it a target hostname
            this.transportLayer.setKeyStoreLocation(config
                    .get(KEYSTORELOCATION));
            this.transportLayer.setKeyStorePW(config.get(KEYSTOREPW));
        }
        catch(ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new KMIPClientException("Configuration error", e);
        }
	}

	public KMIPEncoderInterface getEncoder() {
		return encoder;
	}

	public void setEncoder(KMIPEncoderInterface encoder) {
		this.encoder = encoder;
	}

	public KMIPDecoderInterface getDecoder() {
		return decoder;
	}

	public void setDecoder(KMIPDecoderInterface decoder) {
		this.decoder = decoder;
	}

	public KMIPStubTransportLayerInterface getTransportLayer() {
		return transportLayer;
	}

	public void setTransportLayer(KMIPStubTransportLayerInterface transportLayer) {
		this.transportLayer = transportLayer;
	}

	public Configuration getConfig() {
		return config;
	}

	public void setConfig(Configuration config) {
		this.config = config;
	}

	private Class<?> getClass(String path, String defaultPath)
			throws ClassNotFoundException {
		return Class.forName(KMIPUtils.getClassPath(path, defaultPath));
	}

	/**
	 * Processes a KMIP-Request-Message stored in a <code>KMIPContainer</code>
	 * and returns a corresponding KMIP-Response-Message.
	 * 
	 * @param c
	 *            : the <code>KMIPContainer</code> to be encoded and sent.
	 * @return <code>KMIPContainer</code> with the response objects.
	 */
    @Override
	public KMIPContainer processRequest(KMIPContainer c) throws KMIPClientException {
		ArrayList<Byte> ttlv = encoder.encodeRequest(c);
		ArrayList<Byte> responseFromServer = transportLayer.send(ttlv);
        if(responseFromServer == null ) {
            log.error("Received null response from server");
            return null;
        }
		log.debug("Encoded Response from Server: {}", Hex.encodeHexString(toByteArray(responseFromServer)));
		return decodeResponse(responseFromServer);
	}

	/**
	 * Processes a KMIP-Request-Message stored in a <code>KMIPContainer</code>
	 * and returns a corresponding KMIP-Response-Message. For test cases, there
	 * are two additional parameters that may be set by the caller. The idea is,
	 * that the generated TTLV-Strings can be compared to the expected
	 * TTLV-Strings.
	 * 
	 * @param c
	 *            : the <code>KMIPContainer</code> to be encoded and sent.
	 * @param expectedTTLVRequest
	 *            : the <code>String</code> to be compared to the encoded
	 *            request message.
	 * @param expectedTTLVResponse
	 *            : the <code>String</code> to be compared to the decoded
	 *            response message.
	 * @return <code>KMIPContainer</code> with the response objects.
	 */
    @Override
	public KMIPContainer processRequest(KMIPContainer c,
			String expectedTTLVRequest, String expectedTTLVResponse) throws KMIPClientException {
		// encode Request
		ArrayList<Byte> ttlv = encoder.encodeRequest(c);
		log.debug("Encoded Request from Client: {}", Hex.encodeHexString(toByteArray(ttlv)));
//		KMIPUtils.printArrayListAsHexString(ttlv);
		log.debug("Expected TTLV request: {}", expectedTTLVRequest);
		UCStringCompare.checkRequest(ttlv, expectedTTLVRequest);

		// send Request and check Response
		ArrayList<Byte> responseFromServer = transportLayer.send(ttlv);
        if(responseFromServer == null ) {
            log.error("Received null response from server");
            return null;
        }
		log.debug("Encoded Response from Server: {}", Hex.encodeHexString(toByteArray(responseFromServer)));
//		KMIPUtils.printArrayListAsHexString(responseFromServer);
		log.debug("Expected TTLV request: {}", expectedTTLVResponse);
		UCStringCompare.checkResponse(responseFromServer, expectedTTLVResponse);
		return decodeResponse(responseFromServer);
	}

	private KMIPContainer decodeResponse(ArrayList<Byte> responseFromServer) throws KMIPClientException {
		try {
			return decoder.decodeResponse(responseFromServer);
		} catch (KMIPUnexpectedTypeException | KMIPUnexpectedTagException | KMIPPaddingExpectedException | KMIPProtocolVersionException | UnsupportedEncodingException | KMIPUnexpectedAttributeNameException | NullPointerException e) {
            throw new KMIPClientException("Cannot decode server response", e);
		}
	}
    
    private byte[] toByteArray(List<Byte> byteList) {
        byte[] array = new byte[byteList.size()];
        for(int i=0; i<array.length; i++) {
            array[i] = byteList.get(i);
        }
        return array;
    }

}
