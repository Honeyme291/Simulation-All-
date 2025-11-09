package Tseng21;

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

public class Tseng21 {

    public static void setup(String pairingFile, String publicFile,String mskFile,String PKG) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element g = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("g",g.toString());
        Element gT = bp.pairing(g,g).getImmutable();
        PubProp.setProperty("gT",gT.toString());
        storePropToFile(PubProp,publicFile);

        Properties mskProp = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        Element t = bp.getZr().newRandomElement().getImmutable();
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element v = bp.getZr().newRandomElement().getImmutable();
        Element w = bp.getZr().newRandomElement().getImmutable();
        Element m = bp.getZr().newRandomElement().getImmutable();
        Element n = bp.getZr().newRandomElement().getImmutable();
        Element h = bp.getZr().newRandomElement().getImmutable();
        //系统私钥SS 公钥SP
        Element SS = g.powZn(t).getImmutable();
        Element SP = gT.powZn(t).getImmutable();
        //设置系统私钥对
        Element SS0_1 = g.powZn(a).getImmutable().getImmutable();
        Element SS0_2 = SS.mul(g.powZn(a.invert())).getImmutable();
        Element V = g.powZn(v).getImmutable();
        Element W = g.powZn(w).getImmutable();
        Element M = g.powZn(m).getImmutable();
        Element N = g.powZn(n).getImmutable();

        mskProp.setProperty("SS_"+PKG, Base64.getEncoder().encodeToString(SS.toBytes()));
        mskProp.setProperty("SS01_"+PKG, Base64.getEncoder().encodeToString(SS0_1.toBytes()));
        mskProp.setProperty("SS02_"+PKG, Base64.getEncoder().encodeToString(SS0_2.toBytes()));
        storePropToFile(mskProp, mskFile);

        PubProp.setProperty("SP_", SP.toString());
        PubProp.setProperty("V_", V.toString());
        PubProp.setProperty("W_", W.toString());
        PubProp.setProperty("M_", M.toString());
        PubProp.setProperty("N_", N.toString());
        PubProp.setProperty("h", h.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段,客户端和服务器的注册过程一致
    public static void Extract(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String PKG,String C) throws NoSuchAlgorithmException {


        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String gstr=pubProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();
        String gTstr=pubProp.getProperty("gT");
        Element gT = bp.getGT().newElementFromBytes(gTstr.getBytes()).getImmutable();
        String hstr=pubProp.getProperty("h");
        Element h = bp.getZr().newElementFromBytes(hstr.getBytes()).getImmutable();
        String Vstr=pubProp.getProperty("V_");
        Element V = bp.getG1().newElementFromBytes(Vstr.getBytes()).getImmutable();
        String Wstr=pubProp.getProperty("W_");
        Element W = bp.getG1().newElementFromBytes(Wstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties mskProp=loadPropFromFile(mskFile);
        Properties skp=loadPropFromFile(skFile);
        //PKG获取系统主私钥对
        String SS01str=mskProp.getProperty("SS01_"+PKG);
        Element SS01=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SS01str)).getImmutable();
        String SS02str=mskProp.getProperty("SS02_"+PKG);
        Element SS02=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SS02str)).getImmutable();
        //PKG更新系统私钥对
        Element ac=bp.getZr().newRandomElement().getImmutable();
        Element SSc1=SS01.mul(g.powZn(ac)).getImmutable();
        Element SSc2=SS02.mul(g.powZn(ac.invert())).getImmutable();
        //PKG为客户C计算第一个公私钥
        Element bc=bp.getZr().newRandomElement().getImmutable();
        Element XUc=h.mul(bc).getImmutable();
        Element QUc=gT.powZn(XUc).getImmutable();
        Element IDc=bp.getZr().newElementFromBytes(C.getBytes()).getImmutable();
        Element QIDc=QUc.powZn(IDc).getImmutable();
        Element PIDc=IDc.getImmutable();
        //PKG计算客户端C的第二个公私钥
        Element STc=SSc1.mul(V.mul(W.powZn(PIDc).powZn(bc))).getImmutable();
        Element SUc=SSc2.mul(STc).getImmutable();
        Element QTc=g.powZn(bc).getImmutable();

        //C收到公私钥后计算自己的两个私钥对
        Element yc=bp.getZr().newRandomElement().getImmutable();
        Element XUc01=h.mul(yc).getImmutable();
        Element XUc02=XUc.mul(h.mul(yc.invert())).getImmutable();
        Element SUc01=SUc.mul(g.powZn(yc)).getImmutable();
        Element SUc02=g.powZn(yc.invert()).getImmutable();

        pkp.setProperty("PID_"+C,PIDc.toString());
        pkp.setProperty("QT_"+C,QTc.toString());
        pkp.setProperty("QU_"+C,QUc.toString());
        skp.setProperty("XU--1_"+C,Base64.getEncoder().encodeToString(XUc01.toBytes()));
        skp.setProperty("XU--2_"+C,Base64.getEncoder().encodeToString(XUc02.toBytes()));
        skp.setProperty("SU--1_"+C,Base64.getEncoder().encodeToString(SUc01.toBytes()));
        skp.setProperty("SU--2_"+C,Base64.getEncoder().encodeToString(SUc02.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(mskProp,mskFile);
        storePropToFile(skp,skFile);

    }

    public static void AKA(String pairingFile,String publicFile,String pkFile,String skFile,String veriFile,String C,String S) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String gstr=pubProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(gstr.getBytes()).getImmutable();
        String gTstr=pubProp.getProperty("gT");
        Element gT = bp.getGT().newElementFromBytes(gTstr.getBytes()).getImmutable();
        String SPstr=pubProp.getProperty("SP_");
        Element SP=bp.getGT().newElementFromBytes(SPstr.getBytes()).getImmutable();
        String hstr=pubProp.getProperty("h");
        Element h = bp.getZr().newElementFromBytes(hstr.getBytes()).getImmutable();
        String Vstr=pubProp.getProperty("V_");
        Element V = bp.getG1().newElementFromBytes(Vstr.getBytes()).getImmutable();
        String Wstr=pubProp.getProperty("W_");
        Element W = bp.getG1().newElementFromBytes(Wstr.getBytes()).getImmutable();
        String Mstr=pubProp.getProperty("M_");
        Element M = bp.getG1().newElementFromBytes(Mstr.getBytes()).getImmutable();
        String Nstr=pubProp.getProperty("N_");
        Element N = bp.getG1().newElementFromBytes(Nstr.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        //获取假名
        String PIDcstr=pkp.getProperty("PID_"+C);
        Element PIDc0=bp.getG1().newElementFromBytes(PIDcstr.getBytes()).getImmutable();//字符串转换为element
        String PIDsstr=pkp.getProperty("PID_"+S);
        Element PIDs0=bp.getG1().newElementFromBytes(PIDsstr.getBytes()).getImmutable();

        ////获取C和S的公私钥
        String QTcstr=pkp.getProperty("QT_"+C);
        Element QTc=bp.getG1().newElementFromBytes(QTcstr.getBytes()).getImmutable();
        String QUcstr=pkp.getProperty("QU_"+C);
        Element QUc=bp.getGT().newElementFromBytes(QUcstr.getBytes()).getImmutable();
        String QTsstr=pkp.getProperty("QT_"+S);
        Element QTs=bp.getG1().newElementFromBytes(QTsstr.getBytes()).getImmutable();
        String QUsstr=pkp.getProperty("QU_"+S);
        Element QUs=bp.getGT().newElementFromBytes(QUsstr.getBytes()).getImmutable();
            //私钥
        Properties skp=loadPropFromFile(skFile);
        String XUc01str=skp.getProperty("XU--1_"+C);
        Element XUc01=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(XUc01str)).getImmutable();
        String XUc02str=skp.getProperty("XU--2_"+C);
        Element XUc02=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(XUc02str)).getImmutable();
        String SUc01str=skp.getProperty("SU--1_"+C);
        Element SUc01=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SUc01str)).getImmutable();
        String SUc02str=skp.getProperty("SU--2_"+C);
        Element SUc02=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SUc02str)).getImmutable();
        String XUs01str=skp.getProperty("XU--1_"+S);
        Element XUs01=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(XUs01str)).getImmutable();
        String XUs02str=skp.getProperty("XU--2_"+S);
        Element XUs02=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(XUs02str)).getImmutable();
        String SUs01str=skp.getProperty("SU--1_"+S);
        Element SUs01=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SUs01str)).getImmutable();
        String SUs02str=skp.getProperty("SU--2_"+S);
        Element SUs02=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SUs02str)).getImmutable();

        //PKG为C、S更新密钥------------------------------------------------------------
        Element dc=bp.getZr().newRandomElement().getImmutable();
        Element ds=bp.getZr().newRandomElement().getImmutable();
        Element SUck1=SUc01.mul(g.powZn(dc)).getImmutable();
        Element SUck2=SUc02.mul(g.powZn(dc.invert())).getImmutable();
        Element XUck1=XUc01.mul(h.mul(dc)).getImmutable();
        Element XUck2=XUc02.mul(h.mul(dc.invert())).getImmutable();
        Element SUsl1=SUs01.mul(g.powZn(ds)).getImmutable();
        Element SUsl2=SUs02.mul(g.powZn(ds.invert())).getImmutable();
        Element XUsl1=XUs01.mul(h.mul(ds)).getImmutable();
        Element XUsl2=XUs02.mul(h.mul(ds.invert())).getImmutable();
        //认证和密钥协商，包括四个步骤
        //step 1.
        Element x=bp.getZr().newRandomElement().getImmutable();
        Element X=g.powZn(x).getImmutable();
        Element IDs=bp.getZr().newElementFromBytes(S.getBytes()).getImmutable();
        Element QIDs=QUs.powZn(IDs).getImmutable();
        Element PIDs=IDs.getImmutable();
        Element Kck3=bp.pairing(QTs,V.mul(W.powZn(PIDs))).powZn(x).mul(SP.powZn(x)).getImmutable();
        Element KTck4= QUs.powZn(XUck1).getImmutable();
        Element Kck4=KTck4.powZn(XUc02).getImmutable();
        //Ui选择随机数并计算签名值
        Element nc=bp.getZr().newRandomElement().getImmutable();
        Element Sigc=SUck1.mul(SUck2).mul(M.mul(N.powZn(nc)).powZn(x)).getImmutable();
        //end step 1,C发送 IDc QUc QTc X nc sigc给S

        //step 2
        Element IDc=bp.getZr().newElementFromBytes(C.getBytes()).getImmutable();
        Element QIDc=QUc.powZn(IDc).getImmutable();
        Element PIDc=IDc.getImmutable();
        Element left=bp.pairing(g,Sigc).getImmutable();
        Element right=SP.mul(bp.pairing(X,M.mul(N.powZn(nc)))).mul(bp.pairing(QTc,V.mul(W.powZn(PIDc)))).getImmutable();
        if(left.isEqual(right)){
            out.println("S验证C成功");
        }
        Element y=bp.getZr().newRandomElement().getImmutable();
        Element Y1=g.powZn(y).getImmutable();
        Element Y2=gT.powZn(y).getImmutable();
        //S计算SSKsl会话密钥
        Element Ksl1=X.powZn(y).getImmutable();
        Element Ksl2=QUc.powZn(y).getImmutable();
        Element KTsl3=bp.pairing(X,SUsl1).getImmutable();
        Element KTsl4=QUc.powZn(XUsl1).getImmutable();
        Element Ksl3=KTsl3.mul(bp.pairing(X,SUsl2)).getImmutable();
        Element Ksl4=KTsl4.powZn(XUsl2).getImmutable();
        byte[] bKsl1=Ksl1.toBytes();
        byte[] bKsl2=Ksl2.toBytes();
        byte[] bKsl3=Ksl3.toBytes();
        byte[] bKsl4=Ksl4.toBytes();
        int h0 = Math.max(bKsl1.length, bKsl2.length);
        int l0 = Math.min(bKsl1.length,bKsl2.length);
        byte[] bK12=new byte[h0];
        for (int i=0;i<l0;i++)
            bK12[i]= (byte) (bKsl1[i]^bKsl2[i]);
        int h1 = Math.max(bK12.length, bKsl3.length);
        int l1 = Math.min(bK12.length,bKsl3.length);
        byte[] bK123=new byte[h1];
        for (int i=0;i<l1;i++)
            bK123[i]= (byte) (bK12[i]^bKsl3[i]);
        int h2 = Math.max(bK123.length, bKsl4.length);
        int l2 = Math.min(bK123.length,bKsl4.length);
        byte[] bK1234=new byte[h2];
        for (int i=0;i<l2;i++)
            bK1234[i]= (byte) (bK123[i]^bKsl4[i]);
        Element SSKsl=bp.getZr().newElementFromBytes(bK1234).getImmutable();
        Element ns=bp.getZr().newRandomElement().getImmutable();//nouce时间戳
        //end step2,发送Y1 Y2 Auths ns给C

        //step 3.
        Element Kck1=Y1.powZn(x).getImmutable();
        Element KTck2=Y2.powZn(XUck1).getImmutable();
        Element Kck2=KTck2.powZn(XUck2).getImmutable();
        byte[] bKck1=Ksl1.toBytes();
        byte[] bKck2=Ksl2.toBytes();
        byte[] bKck3=Ksl3.toBytes();
        byte[] bKck4=Ksl4.toBytes();
        int h3 = Math.max(bKck1.length, bKck2.length);
        int l3 = Math.min(bKck1.length,bKsl2.length);
        byte[] bKc12=new byte[h3];
        for (int i=0;i<l3;i++)
            bKc12[i]= (byte) (bKck1[i]^bKck2[i]);
        int h4 = Math.max(bKc12.length, bKck3.length);
        int l4 = Math.min(bKc12.length,bKck3.length);
        byte[] bKc123=new byte[h4];
        for (int i=0;i<l4;i++)
            bKc123[i]= (byte) (bKc12[i]^bKck3[i]);
        int h5 = Math.max(bKc123.length, bKck4.length);
        int l5 = Math.min(bKc123.length,bKck4.length);
        byte[] bKc1234=new byte[h5];
        for (int i=0;i<l5;i++)
            bKc1234[i]= (byte) (bKc123[i]^bKck4[i]);
        Element SSKck=bp.getZr().newElementFromBytes(bKc1234).getImmutable();
        byte[] bh2=sha1(SSKck.toString()+ns.toString());
        Element Authc=bp.getZr().newElementFromHash(bh2,0,bh2.length).getImmutable();
        //end step 3, C发送Authc

        //step 4.
        byte[] bh3=sha1(SSKck.toString()+ns.toString());
        Element Authc1=bp.getZr().newElementFromHash(bh3,0,bh3.length).getImmutable();
        if(Authc.isEqual(Authc1)){
            out.println("S验证C成功");
        }

        Properties verip=loadPropFromFile(veriFile);
        verip.setProperty("SSK_"+C,SSKck.toString());
        verip.setProperty("SSK"+S,SSKsl.toString());
        storePropToFile(verip,veriFile);
        storePropToFile(pubProp,publicFile);
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
        String dir = "./storeFile/Tseng21/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String verifyFileName=dir+"Veri.properties";
        String PKG = "privateKeyGenerator";
        String C="clientC";
        String S="serverS";


        for (int i = 0; i < 10; i++) {//AKA阶段涉及密钥更新
            long start = System.currentTimeMillis();
            long start0 = System.currentTimeMillis();
            setup(pairingParametersFileName,publicParameterFileName,mskFileName,PKG);
            long end0 = System.currentTimeMillis();
            System.out.println(end0 - start0);
            long start1 = System.currentTimeMillis();
            Extract(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,PKG,C);
            Extract(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,PKG,S);
            long end1 = System.currentTimeMillis();
            System.out.println(end1 - start1);
            long start2 = System.currentTimeMillis();
            AKA(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,verifyFileName,C,S);
            long end2 = System.currentTimeMillis();
            System.out.println(end2 - start2);
            long end = System.currentTimeMillis();
            System.out.println(end - start+"total");
        }


    }
}
