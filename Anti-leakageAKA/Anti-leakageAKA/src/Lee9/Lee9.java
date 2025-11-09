package Lee9;

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

import static java.lang.System.currentTimeMillis;
import static java.lang.System.out;

public class Lee9 {

    public static void setup(String pairingFile, String publicFile,String mskFile,String RC) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P",P.toString());
        Element g=bp.pairing(P,P).getImmutable();
        PubProp.setProperty("g",g.toString());
        storePropToFile(PubProp,publicFile);

        Properties mskProp = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        //设置主私钥
        Element s = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        Element s1 = bp.getZr().newRandomElement().getImmutable();
        mskProp.setProperty("s_"+RC, Base64.getEncoder().encodeToString(s.toBytes()));
        mskProp.setProperty("s1_"+RC, Base64.getEncoder().encodeToString(s1.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);
        //设置主公钥
        Element P_pub = P.powZn(s).getImmutable();
        PubProp.setProperty("P_pub_", P_pub.toString());
        Element P_pub1 = P.powZn(s1).getImmutable();
        PubProp.setProperty("P_pub1_", P_pub1.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段
    public static void Registration_User(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RC,String U_i) throws NoSuchAlgorithmException {

        //获得RC的公钥和私钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        Properties mskProp=loadPropFromFile(mskFile);
        String Pstr=pubProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        String sstr=mskProp.getProperty("s_"+RC);
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sstr)).getImmutable();
        String s1str=mskProp.getProperty("s1_"+RC);
        Element s1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s1str)).getImmutable();

        //Ui发送IDI ηi给RC
        Element IDi=bp.getZr().newElementFromBytes(U_i.getBytes()).getImmutable();//字符串转换为element,获取用户U的身份
        Element ui=bp.getZr().newRandomElement().getImmutable();
        Element vi=bp.getZr().newRandomElement().getImmutable();
        Element BIOi=bp.getZr().newRandomElement().getImmutable();
        byte[] bh0_i=sha1(IDi.toString()+ui.toString());
        Element ni=bp.getZr().newElementFromHash(bh0_i,0,bh0_i.length).getImmutable();
        //RC发送SIDi Ri给Ui
        Element ri=bp.getZr().newRandomElement().getImmutable();
        Element Ri = P.powZn(ri).getImmutable();
        byte[] bh1_i=sha1(IDi.toString()+Ri.toString());
        Element h1i=bp.getZr().newElementFromHash(bh1_i,0,bh1_i.length).getImmutable();
        Element SIDi=ri.add(s1.mul(h1i)).getImmutable();
        //Ui do
        Element PWi=bp.getZr().newRandomElement().getImmutable();
        //PWi=PWi.add(IDi).getImmutable();
        byte[] bh3_i=sha1(IDi.toString()+PWi.toString()+ui.toString());
        Element Ci=bp.getZr().newElementFromHash(bh3_i,0,bh3_i.length).getImmutable();
        byte[] bCi= Ci.toBytes();
        byte[] bSIDi=SIDi.toBytes();
        int n = Math.max(bSIDi.length, bCi.length);
        int m = Math.min(bSIDi.length, bCi.length);
        byte[] bDi=new byte[n];
        for (int i=0;i<m;i++)
            bDi[i]= (byte) (bSIDi[i]^bCi[i]);
        Element Di=bp.getZr().newElementFromHash(bDi,0,bDi.length).getImmutable();
        byte[] bRi= Ri.toBytes();
        int n1 = Math.max(bRi.length, bh0_i.length);
        int m1 = Math.min(bRi.length, bh0_i.length);
        byte[] bEi=new byte[n1];
        for (int i=0;i<m1;i++)
            bEi[i]= (byte) (bRi[i]^bh0_i[i]);
        Element Ei=bp.getZr().newElementFromHash(bEi,0,bEi.length).getImmutable();
        byte[] bh4_i=sha1(Ci.toString());
        Element Fi=bp.getZr().newElementFromHash(bh4_i,0,bh4_i.length).getImmutable();

        pkp.setProperty("Di_"+U_i,Di.toString());
        pkp.setProperty("Ei_"+U_i,Ei.toString());
        pkp.setProperty("Fi_"+U_i,Fi.toString());
        skp.setProperty("IDi_"+U_i,Base64.getEncoder().encodeToString(IDi.toBytes()));
        skp.setProperty("ui_"+U_i,Base64.getEncoder().encodeToString(ui.toBytes()));
        skp.setProperty("vi_"+U_i,Base64.getEncoder().encodeToString(vi.toBytes()));
        skp.setProperty("BIOi_"+U_i,Base64.getEncoder().encodeToString(BIOi.toBytes()));
        skp.setProperty("PWi_"+U_i,Base64.getEncoder().encodeToString(PWi.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);
        storePropToFile(pubProp,publicFile);
        storePropToFile(mskProp,mskFile);

    }
    public static void Registration_MEC(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RC,String MEC_j) throws NoSuchAlgorithmException {

        //获得RC的公钥和私钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String gstr=pubProp.getProperty("g");
        String P_pubstr=pubProp.getProperty("P_pub_");
        String P_pub1str=pubProp.getProperty("P_pub1_");
        Element P = bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();
        Element P_pub1 = bp.getG1().newElementFromBytes(P_pub1str.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        Properties mskProp=loadPropFromFile(mskFile);
        String sstr=mskProp.getProperty("s_"+RC);
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sstr)).getImmutable();
        String s1str=mskProp.getProperty("s1_"+RC);
        Element s1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s1str)).getImmutable();

        //MEC
        Element IDj=bp.getZr().newElementFromBytes(MEC_j.getBytes()).getImmutable();//字符串转换为element,获取用户U的身份
        //RC发送SIDj给MECj
        byte[] bh5_j=sha1(IDj.toString());
        Element h5j=bp.getZr().newElementFromHash(bh5_j,0,bh5_j.length).getImmutable();
        Element SIDj=P.powZn(s1.add(h5j).invert()).getImmutable();
        skp.setProperty("IDj_"+MEC_j,Base64.getEncoder().encodeToString(IDj.toBytes()));
        pkp.setProperty("SIDj_"+MEC_j,SIDj.toString());
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);
        storePropToFile(pubProp,publicFile);
        storePropToFile(mskProp,mskFile);

    }
    //Ui和MECj相互认证，不需要RC的帮助
    public static void LoginAndIDAuth(String pairingFile,String publicFile,String pkFile,String skFile,String U_i,String MEC_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String gstr=pubProp.getProperty("g");
        String P_pubstr=pubProp.getProperty("P_pub_");
        String P_pub1str=pubProp.getProperty("P_pub1_");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();
        Element P_pub1 = bp.getG1().newElementFromBytes(P_pub1str.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        String uistr=skp.getProperty("ui_"+U_i);
        Element ui=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(uistr)).getImmutable();
        String Distr=pkp.getProperty("Di_"+U_i);
        Element Di=bp.getZr().newElementFromBytes(Distr.getBytes()).getImmutable();
        String Eistr=pkp.getProperty("Ei_"+U_i);
        Element Ei=bp.getZr().newElementFromBytes(Eistr.getBytes()).getImmutable();
        String Fistr=pkp.getProperty("Fi_"+U_i);
        Element Fi=bp.getZr().newElementFromBytes(Fistr.getBytes()).getImmutable();
        String PWistr=skp.getProperty("PWi_"+U_i);
        String SIDjstr=pkp.getProperty("SIDj_"+MEC_j);
        Element SIDj=bp.getG1().newElementFromBytes(SIDjstr.getBytes()).getImmutable();
        Element PWi=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(PWistr)).getImmutable();
        String IDistr=skp.getProperty("IDi_"+U_i);
        Element IDi=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDistr)).getImmutable();
        String IDjstr=skp.getProperty("IDj_"+MEC_j);
        Element IDj=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjstr)).getImmutable();
        byte[] bh3_i=sha1(IDi.toString()+PWi.toString()+ui.toString());
        Element Ci=bp.getZr().newElementFromHash(bh3_i,0,bh3_i.length).getImmutable();
        //chesk h4(Ci)=Fi
        byte[] bh4_i=sha1(Ci.toString());
        Element h4i=bp.getZr().newElementFromHash(bh4_i,0, bh4_i.length).getImmutable();
        //Ui恢复长期秘密 SID Ri
        byte[] bDi=Di.toBytes();
        byte[] bCi= Ci.toBytes();
        int n2 = Math.max(bDi.length, bCi.length);
        int m2 = Math.min(bDi.length, bCi.length);
        byte[] bSIDi=new byte[n2];
        for (int i=0;i<m2;i++)
            bSIDi[i]= (byte) (bDi[i]^bCi[i]);
        Element SIDi=bp.getG1().newElementFromHash(bSIDi,0,bSIDi.length).getImmutable();

        byte[] bEi=Ei.toBytes();
        byte[] bh0_i=sha1(IDi.toString()+Ci.toString());
        int n3 = Math.max(bEi.length, bh0_i.length);
        int m3 = Math.min(bEi.length, bh0_i.length);
        byte[] bRi=new byte[n3];
        for (int i=0;i<m2;i++)
            bRi[i]= (byte) (bEi[i]^bh0_i[i]);
        Element Ri=bp.getG1().newElementFromHash(bRi,0,bRi.length).getImmutable();

        Element xi=bp.getZr().newRandomElement().getImmutable();
        Element Xi=g.powZn(xi).getImmutable();
        byte[] bh6_i=sha1(Xi.toString());
        //计算对称密钥
        Element Ki=bp.getZr().newElementFromHash(bh6_i,0,bh6_i.length).getImmutable();
        Element UXi=P.powZn(xi).getImmutable();
        byte[] bh0=sha1(IDi.toString()+ xi.toString());
        Element Li=bp.getZr().newElementFromHash(bh0,0,bh0.length).getImmutable();
        Element Ti=bp.getZr().newRandomElement().getImmutable();
        byte[] bh7=sha1(IDi.toString()+IDj.toString()+Li.toString()+Ti.toString());
        Element h7=bp.getG1().newElementFromHash(bh7,0,bh7.length).getImmutable();
        byte[] bh5=sha1(IDi.toString());
        Element h5IDi=bp.getZr().newElementFromHash(bh5,0,bh5.length).getImmutable();
        Element Mi=P_pub1.add(P.powZn(h5IDi)).powZn(xi).getImmutable();
        Element sigmai=SIDi.add(h7).getImmutable();
        byte[] bAuth=sha1(IDi.toString()+Ri.toString()+Li.toString()+UXi.toString());
        Element Authi=bp.getZr().newElementFromHash(bAuth,0,bAuth.length).getImmutable();
        //Ui将M1：Mi sigmai Authi Ti发给MECj

        //MECj收到M1后，
        Element Xi1=bp.pairing(Mi,SIDj).getImmutable();
        byte[] bh6=sha1(Xi1.toString());
        Element Ki1=bp.getZr().newElementFromHash(bh6,0,bh6.length).getImmutable();
        Element sigmaiP=P.mul(sigmai).getImmutable();
        byte[] bh1=sha1(IDi.toString()+Ri.toString());
        Element h1=bp.getZr().newElementFromHash(bh1,0,bh1.length).getImmutable();
        byte[] bh77=sha1(IDi.toString()+IDj.toString()+Li.toString()+Ti.toString());
        Element h77=bp.getG1().newElementFromHash(bh77,0,bh77.length).getImmutable();
        Element right=P_pub.powZn(h1).add(Ri).add(h77).getImmutable();
        //check sigmaip=right 验证Ui的身份
        Element yj=bp.getZr().newRandomElement().getImmutable();
        Element Yj=UXi.powZn(yj).getImmutable();
        Element MYj=P.powZn(yj).getImmutable();
        //MECj计算会话密钥SKj
        Element Tj=bp.getZr().newRandomElement().getImmutable(); //时间戳
        byte[] bh8=sha1(IDi.toString()+IDj.toString()+Li.toString()+Yj.toString()+Ti.toString()+ Tj.toString());
        Element SKj=bp.getZr().newElementFromHash(bh8,0,bh8.length);
        byte[] bh3=sha1(Ki.toString()+Ri.toString()+SKj.toString());
        Element Authj=bp.getZr().newElementFromHash(bh3,0,bh3.length);
        //MECj发送M2: Authj MYj Tj 给Ui
        Element Yj1=MYj.powZn(xi).getImmutable();
        byte[] bh88=sha1(IDi.toString()+IDj.toString()+Li.toString()+Yj1.toString()+Ti.toString()+ Tj.toString());
        Element SKi=bp.getZr().newElementFromHash(bh88,0,bh88.length);
        byte[] bh33=sha1(Ki.toString()+Ri.toString()+SKi.toString());
        Element Authjj=bp.getZr().newElementFromHash(bh33,0,bh33.length);
        //Ui检查Authj=Authjj?
        if(Authj.isEqual(Authjj)){
            //out.println("SK");
        }
        else{
            out.println("SK失败");
        }
        skp.setProperty("SKi"+U_i,SKi.toString());
        skp.setProperty("SKj"+MEC_j,SKj.toString());
        storePropToFile(skp,skFile);
        storePropToFile(pubProp,publicFile);
        storePropToFile(pkp,pkFile);

    }

    public static void Update(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RC,String U_i) throws NoSuchAlgorithmException {

        //获得RC的公钥和私钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String P_pubstr=pubProp.getProperty("P_pub_");
        String P_pub1str=pubProp.getProperty("P_pub1_");
        Element P = bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();
        Element P_pub1 = bp.getG1().newElementFromBytes(P_pub1str.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        Properties mskProp=loadPropFromFile(mskFile);
        String sstr=mskProp.getProperty("s_"+RC);
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sstr)).getImmutable();
        String s1str=mskProp.getProperty("s1_"+RC);
        Element s1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s1str)).getImmutable();

        //Ui发送IDI ηi给RC
        Element IDi=bp.getZr().newElementFromBytes(U_i.getBytes()).getImmutable();//字符串转换为element,获取用户U的身份
        Element ui=bp.getZr().newRandomElement().getImmutable();
        //ui=ui.add(IDi).getImmutable();
        Element vi=bp.getZr().newRandomElement().getImmutable();
        //vi=vi.add(IDi).getImmutable();
        Element BIOi=IDi.getImmutable();
        byte[] bh0_i=sha1(IDi.toString()+ui.toString());
        Element ni=bp.getZr().newElementFromHash(bh0_i,0,bh0_i.length).getImmutable();
        //RC发送SIDi Ri给Ui
        Element ri=bp.getZr().newRandomElement();
        Element Ri = P.powZn(ri).getImmutable();
        byte[] bh1_i=sha1(IDi.toString()+Ri.toString());
        Element h1i=bp.getZr().newElementFromHash(bh1_i,0,bh1_i.length).getImmutable();
        Element SIDi=ri.add(s1.mul(h1i)).getImmutable();
        //Ui do
        Element PWi=bp.getZr().newRandomElement().getImmutable();
        //PWi=PWi.add(IDi).getImmutable();
        byte[] bh3_i=sha1(IDi.toString()+PWi.toString()+ui.toString());
        Element Ci=bp.getZr().newElementFromHash(bh3_i,0,bh3_i.length).getImmutable();
        byte[] bCi= Ci.toBytes();
        byte[] bSIDi=SIDi.toBytes();
        int n = Math.max(bSIDi.length, bCi.length);
        int m = Math.min(bSIDi.length, bCi.length);
        byte[] bDi=new byte[n];
        for (int i=0;i<m;i++)
            bDi[i]= (byte) (bSIDi[i]^bCi[i]);
        Element Di=bp.getZr().newElementFromHash(bDi,0,bDi.length).getImmutable();
        byte[] bRi= Ri.toBytes();
        int n1 = Math.max(bRi.length, bh0_i.length);
        int m1 = Math.min(bRi.length, bh0_i.length);
        byte[] bEi=new byte[n1];
        for (int i=0;i<m1;i++)
            bEi[i]= (byte) (bRi[i]^bh0_i[i]);
        Element Ei=bp.getZr().newElementFromHash(bEi,0,bEi.length).getImmutable();
        byte[] bh4_i=sha1(Ci.toString());
        Element Fi=bp.getZr().newElementFromHash(bh4_i,0,bh4_i.length).getImmutable();


        pkp.setProperty("Di_"+U_i,Di.toString());
        pkp.setProperty("Ei_"+U_i,Ei.toString());
        pkp.setProperty("Fi_"+U_i,Fi.toString());
        skp.setProperty("IDi_"+U_i,Base64.getEncoder().encodeToString(IDi.toBytes()));
        skp.setProperty("ui_"+U_i,Base64.getEncoder().encodeToString(ui.toBytes()));
        skp.setProperty("vi_"+U_i,Base64.getEncoder().encodeToString(vi.toBytes()));
        skp.setProperty("BIOi_"+U_i,Base64.getEncoder().encodeToString(BIOi.toBytes()));
        skp.setProperty("PWi_"+U_i,Base64.getEncoder().encodeToString(PWi.toBytes()));
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
        String dir = "./storeFile/Lee9/"; //根路径
        String pairingParametersFileName = dir + "a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String RC = "registration";
        String U_i="usei";
        String MEC_j="mobile edge computing server";


        for (int i = 0; i < 10; i++) {
            long start = currentTimeMillis();
            long start0 = currentTimeMillis();
            setup(pairingParametersFileName,publicParameterFileName,mskFileName,RC);
            long end0 = System.currentTimeMillis();
            System.out.println(end0 - start0);
            long start1 = currentTimeMillis();
            Registration_User(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,RC,U_i);
            Registration_MEC(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,RC,MEC_j);
            long end1 = System.currentTimeMillis();
            System.out.println(end1 - start1);
            long start2 = currentTimeMillis();
            LoginAndIDAuth(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,U_i,MEC_j);
            long end2 = System.currentTimeMillis();
            System.out.println(end2 - start2);
            long start3 = currentTimeMillis();
            Update(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,RC,U_i);
            long end3 = System.currentTimeMillis();
            System.out.println(end3 - start3);
            long end = System.currentTimeMillis();
            System.out.println(end - start+"total");
        }


    }
}
