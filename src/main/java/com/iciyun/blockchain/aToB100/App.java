package com.iciyun.blockchain.aToB100;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

/**
 * Hello world!
 *
 */
public class App {
	final HFClient client = HFClient.createNewInstance();
	Channel channel;
	TransactionProposalRequest proposalRequest;

	void setupCryptoMaterialsForClient() throws CryptoException, InvalidArgumentException, IllegalAccessException,
			InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
		// Set default crypto suite for HF client

		client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

		client.setUserContext(new User() {

			@Override
			public String getName() {
				return "PeerAdmin";
			}

			@Override
			public Set<String> getRoles() {
				return null;
			}

			@Override
			public String getAccount() {
				return null;
			}

			@Override
			public String getAffiliation() {
				return null;
			}

			@Override
			public Enrollment getEnrollment() {
				return new Enrollment() {
					@Override
					public PrivateKey getKey() {
						PrivateKey privateKey = null;
						try {
							File privateKeyFile = findFileSk(
									"/opt/gopath/src/github.com/hyperledger/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore");
							privateKey = getPrivateKeyFromBytes(
									IOUtils.toByteArray(new FileInputStream(privateKeyFile)));
						} catch (InvalidKeySpecException e) {
							e.printStackTrace();
						} catch (IOException e) {
							e.printStackTrace();
						} catch (NoSuchProviderException e) {
							e.printStackTrace();
						} catch (NoSuchAlgorithmException e) {
							e.printStackTrace();
						}
						return privateKey;
					}

					@Override
					public String getCert() {

						String certificate = null;
						try {
							File certificateFile = new File(
									"/opt/gopath/src/github.com/hyperledger/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem");
							certificate = new String(IOUtils.toByteArray(new FileInputStream(certificateFile)),
									"UTF-8");
						} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
						} catch (FileNotFoundException e) {
							e.printStackTrace();
						} catch (IOException e) {
							e.printStackTrace();
						}
						return certificate;
					}
				};
			}

			@Override
			public String getMspId() {
				return "Org1MSP";
			}
		});
	}

	static File findFileSk(String directorys) {

		File directory = new File(directorys);

		File[] matches = directory.listFiles((file, name) -> name.endsWith("_sk"));

		if (null == matches) {
			throw new RuntimeException(
					"Matches returned null does %s directory exist?" + directory.getAbsoluteFile().getName());
		}

//		if (matches.length != 1) {
//			throw new RuntimeException("Expected in %s only 1 sk file but found %d"
//					+ directory.getAbsoluteFile().getName() + matches.length);
//		}
		System.out.println(matches[0]);
		System.out.println(matches[1]);
		return matches[1];
	}

	static PrivateKey getPrivateKeyFromBytes(byte[] data)
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		final Reader pemReader = new StringReader(new String(data));

		final PrivateKeyInfo pemPair;
		try (PEMParser pemParser = new PEMParser(pemReader)) {
			pemPair = (PrivateKeyInfo) pemParser.readObject();
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PrivateKey privateKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.getPrivateKey(pemPair);

		return privateKey;
	}

	void createChannel() throws InvalidArgumentException, TransactionException {
		channel = client.newChannel("mychannel");
		Properties ordererProperties = new Properties();
		ordererProperties.setProperty("pemFile",
				"/opt/gopath/src/github.com/hyperledger/fabric-samples/first-network/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt");
		ordererProperties.setProperty("trustServerCertificate", "true"); // testing environment only NOT FOR PRODUCTION!
		ordererProperties.setProperty("hostnameOverride", "orderer.example.com");
		ordererProperties.setProperty("sslProvider", "openSSL");
		ordererProperties.setProperty("negotiationType", "TLS");
		ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] { 5L, TimeUnit.MINUTES });
		ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] { 8L, TimeUnit.SECONDS });
		channel.addOrderer(
				client.newOrderer("orderer.example.com", "grpcs://orderer.example.com:7050", ordererProperties));

		Properties peerProperties = new Properties();
		peerProperties.setProperty("pemFile",
				"/opt/gopath/src/github.com/hyperledger/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt");
		peerProperties.setProperty("trustServerCertificate", "true"); // testing environment only NOT FOR PRODUCTION!
		peerProperties.setProperty("hostnameOverride", "peer0.org1.example.com");
		peerProperties.setProperty("sslProvider", "openSSL");
		peerProperties.setProperty("negotiationType", "TLS");
		peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
		channel.addPeer(
				client.newPeer("peer0.org1.example.com", "grpcs://peer0.org1.example.com:7051", peerProperties));
		channel.initialize();
	}

	void creteTransactionalProposal() {
		proposalRequest = client.newTransactionProposalRequest();

		final ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName("mycc").setVersion("1.0")
				.setPath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02").build();

		proposalRequest.setChaincodeID(chaincodeID);
//		proposalRequest.setFcn("init");
//		proposalRequest.setProposalWaitTime(TimeUnit.SECONDS.toMillis(10));
//		proposalRequest.setArgs(new String[] { "ORG1",
//				"{\"assetKey\":\"a1\",\"assetName\":\"aname1\",\"assetType\":\"atype1\",\"slNo\":\"slno1\",\"orderDate\":\"19-05-2017\"}" });
		proposalRequest.setFcn("invoke");
		proposalRequest.setProposalWaitTime(TimeUnit.SECONDS.toMillis(10));
		proposalRequest.setArgs(new String[] { "a", "b", "100" });
	}

	void sendProposal() throws ProposalException, InvalidArgumentException, InterruptedException, ExecutionException {
		final Collection<ProposalResponse> responses = channel.sendTransactionProposal(proposalRequest);
		CompletableFuture<BlockEvent.TransactionEvent> txFuture = channel.sendTransaction(responses,
				client.getUserContext());
		BlockEvent.TransactionEvent event = txFuture.get();
		System.out.println(event.toString());
	}

	public static void main(String args[]) throws Exception {
		System.out.println("starting...");
		App t = new App();
		t.setupCryptoMaterialsForClient();
		t.createChannel();
//		t.creteTransactionalProposal();
//		t.sendProposal();
		QueryByChaincodeRequest queryByChaincodeRequest = QueryByChaincodeRequest
				.newInstance(t.client.getUserContext());
		final ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName("mycc").setVersion("1.0")
				.setPath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02").build();
		queryByChaincodeRequest.setChaincodeID(chaincodeID);
		queryByChaincodeRequest.setFcn("query");
		queryByChaincodeRequest.setArgs(new String[] { "a" });
		final Collection<ProposalResponse> responses = t.channel.queryByChaincode(queryByChaincodeRequest);
		Iterator<ProposalResponse> it = responses.iterator();
		while (it.hasNext()) {
			ProposalResponse response = it.next();
			System.out.println(response.getMessage());
			System.out.println(new String(response.getChaincodeActionResponsePayload()));
		}
	}
}
