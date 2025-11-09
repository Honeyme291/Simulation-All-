package Ali11;

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

public class Ali11 {

    public static void setup(String pairingFile, String publicFile,String mskFile,String CA) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element g = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("g",g.toString());
        storePropToFile(PubProp,publicFile);

        Properties msk = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        //设置CA
        Element s = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        msk.setProperty("s_"+CA, Base64.getEncoder().encodeToString(s.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(msk, mskFile);

        //设置主公钥
        Element P_pub = g.powZn(s).getImmutable();
        PubProp.setProperty("P_pub_"+CA, P_pub.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段,参与三方认证的用户均需要完成注册过程
    public static void Registration(String pairingFile,String publicFile,String pkFile,String skFile,String User) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String gstr=pubProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //为用户UE/MECs生成公私钥
        Element x=bp.getZr().newRandomElement().getImmutable();
        Element X=g.powZn(x).getImmutable();

        pkp.setProperty("X_"+User,X.toString());
        skp.setProperty("x_"+User,Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }

    public static void Authentication_TC3A(String pairingFile,String publicFile,String pkFile,String skFile,String CA,String MEC_A,String MEC_B,String UE) throws NoSuchAlgorithmException {

        //获得CA的公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String gstr=pubProp.getProperty("g");
        String P_pubstr=pubProp.getProperty("P_pub_"+CA);
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        //获取UE MECA MECB的公私钥
        String X_UEstr=pkp.getProperty("X_"+UE);
        Element X_UE=bp.getG1().newElementFromBytes(X_UEstr.getBytes()).getImmutable();
        String X_Astr=pkp.getProperty("X_"+MEC_A);
        Element X_A=bp.getG1().newElementFromBytes(X_Astr.getBytes()).getImmutable();
        String X_Bstr=pkp.getProperty("X_"+MEC_B);
        Element X_B=bp.getG1().newElementFromBytes(X_Bstr.getBytes()).getImmutable();
            //私钥
        Properties skp=loadPropFromFile(skFile);
        String x_UEstr=skp.getProperty("x_"+UE);
        Element x_UE=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_UEstr)).getImmutable();
        String x_Astr=skp.getProperty("x_"+MEC_A);
        Element x_A=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_Astr)).getImmutable();
        String x_Bstr=skp.getProperty("x_"+MEC_B);
        Element x_B=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_Bstr)).getImmutable();

        //生成公共密钥K
        Element S0=bp.getG1().newRandomElement().getImmutable();//时间戳
        byte[] bh=sha1(X_A.toString()+X_B.toString()+X_UE.toString()+P_pub.toString()+S0.toString());
        Element K=bp.getG1().newElementFromHash(bh,0,bh.length).getImmutable();
        //UE发送认证请求Req
        Element SA=bp.getG1().newRandomElement().getImmutable();
        Element cookie=X_UE.add(X_A).add(SA).getImmutable();
        Element S1=bp.getG1().newRandomElement().getImmutable();//时间戳
        //EMC_A用K对消息进行加密得到vrfy
        byte[] bvrfy=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy=bp.getG1().newElementFromHash(bvrfy,0,bvrfy.length).getImmutable();
        //生成令牌T
        Element T=X_A.add(X_UE.add(S0.add(cookie.add(vrfy)))).getImmutable();
        //UE和MECA交换公钥，计算公共密钥g^au
        Element k_AU=X_A.powZn(x_UE).getImmutable();
        Element k_AU1=X_UE.powZn(x_A).getImmutable();
        //MECA发送消息C_AU给UE
        byte [] bCAU=sha1(T.toString());
        Element C_AU=bp.getG1().newElementFromHash(bCAU,0,bCAU.length).getImmutable();
        //同样地，UE通过K来计算vrfy'以获得T
        byte[] bvrfy1=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy1=bp.getG1().newElementFromHash(bvrfy,0,bvrfy.length).getImmutable();
        Element TT=X_A.add(X_UE.add(S1.add(cookie.add(vrfy1)))).getImmutable();

        //UE离开MECA，去往MECB
            //UE和MECB交换公钥，计算临时公钥k_UB
        Element k_UB=X_UE.powZn(x_B).getImmutable();
        Element k_UB1=X_B.powZn(x_UE).getImmutable();
        //UE发送Req
        Element SB=bp.getG1().newRandomElement().getImmutable();
        //用K对消息进行加密得到vrfy
        byte[] bvrfy2=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy2=bp.getG1().newElementFromHash(bvrfy2,0,bvrfy2.length).getImmutable();
        //令牌T
        Element T2=X_A.add(X_UE.add(S1.add(cookie.add(vrfy2)))).getImmutable();
        //UE生成消息CUB
        byte [] bCUB=sha1(T2.toString());
        Element C_UB=bp.getG1().newElementFromHash(bCUB,0,bCUB.length).getImmutable();
        //MECB获取vrfy'
        byte[] bvrfy3=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy3=bp.getG1().newElementFromHash(bvrfy2,0,bvrfy3.length).getImmutable();
        //then MECB确认
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }
    public static void Authentication_TS3A(String pairingFile,String publicFile,String pkFile,String skFile,String CA,String MEC_A,String MEC_B,String UE,int n) throws NoSuchAlgorithmException {

        //获得CA的公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String gstr=pubProp.getProperty("g");
        String P_pubstr=pubProp.getProperty("P_pub_"+CA);
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        //获取UE MECA MECB的公私钥
        String X_UEstr=pkp.getProperty("X_"+UE);
        Element X_UE=bp.getG1().newElementFromBytes(X_UEstr.getBytes()).getImmutable();
        String X_Astr=pkp.getProperty("X_"+MEC_A);
        Element X_A=bp.getG1().newElementFromBytes(X_Astr.getBytes()).getImmutable();
        String X_Bstr=pkp.getProperty("X_"+MEC_B);
        Element X_B=bp.getG1().newElementFromBytes(X_Bstr.getBytes()).getImmutable();
        //私钥
        Properties skp=loadPropFromFile(skFile);
        String x_UEstr=skp.getProperty("x_"+UE);
        Element x_UE=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_UEstr)).getImmutable();
        String x_Astr=skp.getProperty("x_"+MEC_A);
        Element x_A=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_Astr)).getImmutable();
        String x_Bstr=skp.getProperty("x_"+MEC_B);
        Element x_B=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_Bstr)).getImmutable();

        //生成公共密钥K
        Element S0=bp.getG1().newRandomElement().getImmutable();//时间戳
        byte[] bh=sha1(X_A.toString()+X_B.toString()+X_UE.toString()+P_pub.toString()+S0.toString());
        Element K=bp.getG1().newElementFromHash(bh,0,bh.length).getImmutable();
        //UE1发送认证请求Req
        Element SA=bp.getG1().newRandomElement().getImmutable();
        Element cookie=X_UE.add(X_A).add(SA).getImmutable();
        Element S1=bp.getG1().newRandomElement().getImmutable();//时间戳
        //EMC_A1用K对消息进行加密得到vrfy
        byte[] bvrfy=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy=bp.getG1().newElementFromHash(bvrfy,0,bvrfy.length).getImmutable();
        //生成多个状态令牌T
        Element[] T=new Element[n];
        for(int i=0;i<n;i++){
            Element random=bp.getG1().newRandomElement();
            T[i]=X_A.add(X_UE.add(S0.add(cookie.add(vrfy).add(random)))).getImmutable();
        }
        //UE和MECA交换公钥，计算公共密钥g^au
        Element k_AU=X_A.powZn(x_UE).getImmutable();
        Element k_AU1=X_UE.powZn(x_A).getImmutable();
        //MECA发送消息C_AU给UE
        Element Tsum=bp.getG1().newZeroElement();
        for(int i=0;i<n;i++){
            Tsum=Tsum.add(T[i]);
        }
        byte [] bCAU=sha1(Tsum.toString());
        Element C_AU=bp.getG1().newElementFromHash(bCAU,0,bCAU.length).getImmutable();
        //同样地，UE通过K来计算vrfy'以获得T
        byte[] bvrfy1=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy1=bp.getG1().newElementFromHash(bvrfy,0,bvrfy.length).getImmutable();
        Element[] TT=new Element[n];
        for(int i=0;i<n;i++){
            Element random=bp.getG1().newRandomElement();
            TT[i]=X_A.add(X_UE.add(S0.add(cookie.add(vrfy1).add(random)))).getImmutable();
        }

        //UE离开MECA，去往MECB
        //UE和MECB交换公钥，计算临时公钥k_UB
        Element k_UB=X_UE.powZn(x_B).getImmutable();
        Element k_UB1=X_B.powZn(x_UE).getImmutable();
        //UE发送Req
        Element SB=bp.getG1().newRandomElement().getImmutable();
        //用K对消息进行加密得到vrfy
        byte[] bvrfy2=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy2=bp.getG1().newElementFromHash(bvrfy2,0,bvrfy2.length).getImmutable();
        //令牌T
        Element[] T2=new Element[n];
        for(int i=0;i<n;i++){
            Element random=bp.getG1().newRandomElement();
            T2[i]=X_A.add(X_UE.add(S0.add(cookie.add(vrfy1).add(random)))).getImmutable();
        }
        //UE生成消息CUB
        Element T2sum=bp.getG1().newZeroElement();
        for(int i=0;i<n;i++){
            T2sum=T2sum.add(T2[i]);
        }
        byte [] bCUB=sha1(T2sum.toString());
        Element C_UB=bp.getG1().newElementFromHash(bCUB,0,bCUB.length).getImmutable();
        //MECB获取vrfy'
        byte[] bvrfy3=sha1(K.toString()+X_A.toString()+X_UE.toString()+cookie.toString()+S1.toString());
        Element vrfy3=bp.getG1().newElementFromHash(bvrfy2,0,bvrfy3.length).getImmutable();
        //then MECB确认
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

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
        String dir = "./storeFile/Ali11/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String CA = "CA";
        String UE = "UE";
        String MEC_A="MEC_A";
        String MEC_B="MEC_B";

        int n=20;//TS3A认证模式下，多状态令牌的数量
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            long start0 = System.currentTimeMillis();
            setup(pairingParametersFileName,publicParameterFileName,mskFileName,CA);
            long end0 = System.currentTimeMillis();
            System.out.println(end0 - start0);
            long start1 = System.currentTimeMillis();
            //三方认证，每个用户注册
            Registration(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,UE);
            Registration(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,MEC_A);
            Registration(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,MEC_B);
            long end1 = System.currentTimeMillis();
            System.out.println(end1 - start1);
            long start2 = System.currentTimeMillis();
            //两种认证模式
            Authentication_TC3A(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,CA,MEC_A,MEC_B,UE);
            Authentication_TS3A(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,CA,MEC_A,MEC_B,UE,n);
            long end2 = System.currentTimeMillis();
            System.out.println(end2 - start2);
            long end = System.currentTimeMillis();
            System.out.println(end - start+"total ");
        }


    }
}
