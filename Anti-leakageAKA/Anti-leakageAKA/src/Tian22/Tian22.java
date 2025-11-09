package Tian22;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import static java.lang.System.out;

//import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import java.security.SecureRandom;
import java.util.Arrays;


public class Tian22 {
    private static final int SECRET_LENGTH = 32; // 256 bits
    private static final int PARITY_LENGTH = 32;  // 256 bits
    public static byte[][] fuzzyExtract(byte[] input) {//模糊提取器
        // Hash the input to generate a secret
        byte[] hashedInput = DigestUtils.sha256(input);

        // Generate random parity
        byte[] parity = new byte[PARITY_LENGTH];
        new SecureRandom().nextBytes(parity);

        // Generate the secret
        byte[] secret = Arrays.copyOfRange(hashedInput, 0, SECRET_LENGTH);

        // Combine secret and parity
        byte[] combined = new byte[secret.length + parity.length];
        System.arraycopy(secret, 0, combined, 0, secret.length);
        System.arraycopy(parity, 0, combined, secret.length, parity.length);

        // Return the secret and parity
        return new byte[][]{secret, parity};
    }

    public static byte[] recoverSecret(byte[] input, byte[] parity) {
        // Hash the input to generate a new secret
        byte[] hashedInput = DigestUtils.sha256(input);
        byte[] newSecret = Arrays.copyOfRange(hashedInput, 0, SECRET_LENGTH);

        return newSecret;
    }


    public static void setup(String pairingFile, String publicFile,String mskFile) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P",P.toString());
        storePropToFile(PubProp,publicFile);
    }


    //Registration阶段
    public static void Enrollment(String pairingFile,String publicFile,String pkFile,String skFile,String User) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //为用户U/认证服务器注册
        Element B_User=bp.getZr().newRandomElement().getImmutable();
        byte[] sampleInput = B_User.toBytes();
        byte[][] extracted = fuzzyExtract(sampleInput);
        byte[] recoveredSecret = recoverSecret(sampleInput, extracted[1]);
        Element r1=bp.getZr().newElementFromBytes(recoveredSecret).getImmutable();
        //System.out.println("Secret: " + org.apache.commons.codec.binary.Base64.encodeBase64String(extracted[0]));
        //System.out.println("Parity: " + org.apache.commons.codec.binary.Base64.encodeBase64String(extracted[1]));
        byte[] Secret = extracted[0];
        byte[] Parity = extracted[1];
        Element R_User=bp.getZr().newElementFromBytes(Secret).getImmutable();
        Element P_User=bp.getZr().newElementFromBytes(Parity).getImmutable();

        Element x_User=bp.getZr().newRandomElement().getImmutable();
        Element t1=bp.getZr().newRandomElement().getImmutable();
        Element X_User=P.powZn(x_User).getImmutable();
        Element T1=P.powZn(x_User).getImmutable();
        byte[] bH1_i=sha1(R_User.toString()+User.toString()+X_User.toString()+T1.toString());
        Element H1_i=bp.getZr().newElementFromHash(bH1_i,0,bH1_i.length).getImmutable();
        Element d_Ri=x_User.powZn(H1_i).add(t1).getImmutable();
        Element IDU=bp.getZr().newElementFromBytes(User.getBytes()).getImmutable();
        //存储key
        pkp.setProperty("B_"+User,B_User.toString());
        pkp.setProperty("X_"+User,X_User.toString());
        pkp.setProperty("R_"+User,R_User.toString());
        pkp.setProperty("P_"+User,P_User.toString());
        skp.setProperty("x_"+User,Base64.getEncoder().encodeToString(x_User.toBytes()));
        skp.setProperty("ID_"+User,Base64.getEncoder().encodeToString(IDU.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }


    public static void Authentication(String pairingFile,String publicFile,String pkFile,String skFile,String certiFile,String U_i,String S_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        //Sj获取用户Ui的身份
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        String IDistr=skp.getProperty("ID_"+U_i);//获取属性
        Element IDi=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(IDistr)).getImmutable();//字符串转换为element
        String IDjstr=skp.getProperty("ID_"+S_j);
        Element IDj=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(IDjstr)).getImmutable();

        //获取各自的公私钥
        String Xistr=pkp.getProperty("X_"+U_i);
        Element Xi=bp.getG1().newElementFromBytes(Xistr.getBytes()).getImmutable();
        String Ristr=pkp.getProperty("R_"+U_i);
        //Element Ri=bp.getG1().newElementFromBytes(Ristr.getBytes()).getImmutable();
        String Pistr=pkp.getProperty("P_"+U_i);
        Element Pi=bp.getG1().newElementFromBytes(Pistr.getBytes()).getImmutable();
        String xistr=skp.getProperty("x_"+U_i);
        Element xi=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xistr)).getImmutable();

        String Xjstr=pkp.getProperty("X_"+S_j);
        Element Xj=bp.getG1().newElementFromBytes(Xjstr.getBytes()).getImmutable();
        String Rjstr=pkp.getProperty("R_"+S_j);
        Element Rj=bp.getG1().newElementFromBytes(Rjstr.getBytes()).getImmutable();
        String Pjstr=pkp.getProperty("P_"+S_j);
        Element Pj=bp.getG1().newElementFromBytes(Pjstr.getBytes()).getImmutable();
        String xjstr=skp.getProperty("x_"+S_j);
        Element xj=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjstr)).getImmutable();
        //Sj do 将Pi rs发送给Ui
        Element rs=bp.getZr().newRandomElement().getImmutable();
        byte[] sampleInput = rs.toBytes();
        byte[][] extracted = fuzzyExtract(sampleInput);
        byte[] recoveredSecret = recoverSecret(sampleInput, extracted[1]);
        Element ri=bp.getZr().newElementFromBytes(recoveredSecret).getImmutable();
        byte[] bP = extracted[1];
        Element Pii=bp.getZr().newElementFromBytes(bP).getImmutable();

        //Ui do
        String Bistr=pkp.getProperty("B_"+U_i);
        Element Bi=bp.getG1().newElementFromBytes(Bistr.getBytes()).getImmutable();
        byte[] recoveredSecret1 = recoverSecret(sampleInput,bP);
            //从模糊提取器恢复Ri
        Element Ri1=bp.getG1().newElementFromBytes(recoveredSecret1).getImmutable();
            //Ui基于Ri(Ri1)再次运行keyGen
        Element x_i=bp.getZr().newRandomElement().getImmutable();
        Element t2=bp.getZr().newRandomElement().getImmutable();
        Element X_i=P.powZn(x_i).getImmutable();
        Element T2=P.powZn(x_i).getImmutable();
        byte[] bh1_i=sha1(Ri1.toString()+U_i.toString()+X_i.toString()+T2.toString());
        Element h1_i=bp.getZr().newElementFromHash(bh1_i,0,bh1_i.length).getImmutable();
        Element d_i=x_i.powZn(h1_i).add(t2).getImmutable();
            //Ui根据获取ri
        byte[][] extracted2 = fuzzyExtract(sampleInput);
        byte[] recoveredSecret2 = recoverSecret(sampleInput, extracted[1]);
        Element rii=bp.getZr().newElementFromBytes(recoveredSecret2).getImmutable();
            //Ui计算证书
        Element q=bp.getZr().newRandomElement().getImmutable();
        byte[] bhi=sha1(IDi.toString()+rs.toString()+q.toString()+rii.toString());
        Element rc=bp.getZr().newElementFromHash(bhi,0,bhi.length).getImmutable();
        //final Ui发送rc q

        //Sj do
        byte[] bhj=sha1(IDi.toString()+rs.toString()+q.toString()+ri.toString());
        Element rc1=bp.getZr().newElementFromHash(bhj,0,bhj.length).getImmutable();
            //判断rc==rc1
        if(rc.isEqual(rc1)){
            out.println("Sj接收Ui");
        }

        Properties certip=loadPropFromFile(certiFile);//存储证书

        certip.setProperty("ri_"+U_i,ri.toString());
        certip.setProperty("rc_"+U_i,rc.toString());
        certip.setProperty("rc_"+S_j,rc1.toString());
        storePropToFile(certip,certiFile);


    }



    /*
    将程序变量数据存储到文件中
     */
    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }


    /*
    从文件中读取数据
     */
    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }


    /*
    哈希函数
     */
    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }
    public static byte[] sha2(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(content.getBytes());
        return instance.digest();
    }
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
        指定配置文件的路径
         */
        String dir = "./storeFile/Tian22/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String certificateFileName=dir+"certi.properties";


        String U_i="useri";
        String S_j="AuthenticationServerj";
        String B="BI";
        String S_k="expand";

        for (int i = 0; i < 10; i++) { //该方案仅实现了单向认证
            long start = System.currentTimeMillis();
            long start0 = System.currentTimeMillis();
            setup(pairingParametersFileName,publicParameterFileName,mskFileName);
            long end0 = System.currentTimeMillis();
            System.out.println(end0 - start0);
            long start1 = System.currentTimeMillis();
            Enrollment(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,U_i);
            Enrollment(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,S_j);
            Enrollment(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,B);
            Enrollment(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,S_k);
            long end1 = System.currentTimeMillis();
            System.out.println(end1 - start1);
            long start2 = System.currentTimeMillis();
            Authentication(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,certificateFileName,U_i,S_j);
            Authentication(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,certificateFileName,B,S_k);
            long end2 = System.currentTimeMillis();
            System.out.println(end2 - start2);
            long end = System.currentTimeMillis();
            System.out.println(end - start+"_total");
        }


    }
}
