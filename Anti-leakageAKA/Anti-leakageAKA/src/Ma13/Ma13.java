package Ma13;

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

public class Ma13 {

    public static void setup(String pairingFile, String publicFile,String mskFile,String RC) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P",P.toString());
        storePropToFile(PubProp,publicFile);

        Properties mskProp = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        //设置系统的主私钥
        Element s = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        mskProp.setProperty("s_"+RC, Base64.getEncoder().encodeToString(s.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);

        //设置主公钥
        Element P_pub = P.powZn(s).getImmutable();
        PubProp.setProperty("P_pub_"+RC, P_pub.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段,用户或者边缘计算服务器向RC注册，二者的注册过程完全一致
    public static void Registration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RC,String User) throws NoSuchAlgorithmException {

        //获得RC的公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String P_pubstr=pubProp.getProperty("P_pub_"+RC);
        Element P = bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        Properties msk=loadPropFromFile(mskFile);
        //获得RC的私钥
        String sstr = msk.getProperty("s_" + RC);
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sstr)).getImmutable();
        //用户发送其身份ID和一个随机数x给RC
        Element IDU=bp.getZr().newElementFromBytes(User.getBytes()).getImmutable();
        Element x=bp.getZr().newRandomElement().getImmutable();
        Element X=P.powZn(x).getImmutable();
        //RC收到ID和X,为用户生成密钥
        Element r=bp.getZr().newRandomElement().getImmutable();
        Element R=P.powZn(r).getImmutable();
        byte[] bH1=sha1(IDU.toString()+X.toString()+R.toString());
        Element H1=bp.getZr().newElementFromHash(bH1,0,bH1.length).getImmutable();
        Element y=r.add(s.mul(H1)).getImmutable();
        //用户验证y，by
        Element yP=P.powZn(y).getImmutable();
        byte[] bH11=sha1(IDU.toString()+X.toString()+R.toString());
        Element H11=bp.getZr().newElementFromHash(bH11,0,bH11.length).getImmutable();
        Element right=R.add(P_pub.powZn(H11)).getImmutable();
        if(yP.isEqual(right)){
            out.println("密钥验证成功");
        }
        //存储私钥，发布公钥
        pkp.setProperty("X_"+User,X.toString());
        pkp.setProperty("R_"+User,R.toString());
        skp.setProperty("x_"+User,Base64.getEncoder().encodeToString(x.toBytes()));
        skp.setProperty("y_"+User,Base64.getEncoder().encodeToString(y.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }

    //MEC和U进行认证和会话密钥协商
    public static void AKA(String pairingFile,String publicFile,String pkFile,String skFile,String RC,String U_i,String MS_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String P_pubstr=pubProp.getProperty("P_pub_"+RC);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(P_pubstr.getBytes()).getImmutable();

        Element Ui=bp.getG1().newElementFromBytes(U_i.getBytes()).getImmutable();
        Element MSj=bp.getG1().newElementFromBytes(MS_j.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        //获取用户公钥
        String Xistr=pkp.getProperty("X_"+U_i);
        Element Xi=bp.getG1().newElementFromBytes(Xistr.getBytes()).getImmutable();
        String Ristr=pkp.getProperty("R_"+U_i);
        Element Ri=bp.getG1().newElementFromBytes(Ristr.getBytes()).getImmutable();
        String Xjstr=pkp.getProperty("X_"+MS_j);
        Element Xj=bp.getG1().newElementFromBytes(Xjstr.getBytes()).getImmutable();
        String Rjstr=pkp.getProperty("R_"+MS_j);
        Element Rj=bp.getG1().newElementFromBytes(Rjstr.getBytes()).getImmutable();
        //私钥
        Properties skp=loadPropFromFile(skFile);
        String xistr=skp.getProperty("x_"+U_i);
        Element xi=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xistr)).getImmutable();
        String yistr=skp.getProperty("y_"+U_i);
        Element yi=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yistr)).getImmutable();
        String xjstr=skp.getProperty("x_"+MS_j);
        Element xj=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjstr)).getImmutable();
        String yjstr=skp.getProperty("y_"+MS_j);
        Element yj=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yjstr)).getImmutable();

        //Ui向MS_j发消息
        Element a=bp.getZr().newRandomElement().getImmutable();
        Element b=bp.getZr().newRandomElement().getImmutable();
        Element A=P.powZn(a).getImmutable();
        Element B=P.powZn(b).getImmutable();
        byte[] bHsj=sha1(Ui.toString()+Xj.toString()+Rj.toString());
        Element Hsj=bp.getZr().newElementFromHash(bHsj,0,bHsj.length).getImmutable();
        Element M1= Xj.add(Rj.add(P_pub.powZn(Hsj))).getImmutable();
        byte[] bhM1=sha1(M1.toString());
        Element hM1=bp.getZr().newElementFromHash(bhM1,0,bhM1.length).getImmutable();
        Element temp0i=Ui.powZn(A).getImmutable();
        byte[] btemp0i=temp0i.toBytes();
        int n = Math.max(bhM1.length, btemp0i.length);
        int m = Math.min(bhM1.length, btemp0i.length);
        byte[] bM2=new byte[n];
        for (int i=0;i<m;i++)
            bM2[i]= (byte) (bhM1[i]^btemp0i[i]);
        Element M2=bp.getZr().newElementFromHash(bM2,0,bM2.length).getImmutable();
        Element Ti=bp.getG1().newRandomElement().getImmutable();//时间戳
        byte[] bh1i=sha1(Ui.toString()+A.toString()+Ri.toString()+ Ti.toString());
        Element h1i=bp.getZr().newElementFromHash(bh1i,0,bh1i.length).getImmutable();
        Element sigmai= yi.add(b.invert().mul(h1i)).getImmutable();

        //MS_J验证Ui的签名
        Element M11=B.powZn(xj.add(yj)).getImmutable();
        byte[] bhM11=sha1(M11.toString());
        Element hM11=bp.getZr().newElementFromHash(bhM11,0,bhM11.length).getImmutable();
        int n1 = Math.max(bhM11.length, bM2.length);
        int m1 = Math.min(bhM11.length, bM2.length);
        byte[] btempi1=new byte[n1];
        for (int i=0;i<m1;i++)
            btempi1[i]= (byte) (bhM11[i]^bM2[i]);
        Element tempi1=bp.getZr().newElementFromHash(btempi1,0,btempi1.length).getImmutable();
        Element sigmaiP=P.powZn(sigmai).getImmutable();
        byte[] bh1i1=sha1(Ui.toString()+A.toString()+Ri.toString()+ Ti.toString());
        Element h1i1=bp.getZr().newElementFromHash(bh1i1,0,bh1i1.length).getImmutable();
        byte[] bHui=sha1(MSj.toString()+Xi.toString()+Ri.toString());
        Element Hui=bp.getZr().newElementFromHash(bHui,0,bHui.length).getImmutable();
        Element right=P.powZn(h1i1).add(Ri.add(P_pub.powZn(Hui))).getImmutable();
        //sigmaiP=right
        if(sigmaiP.isEqual(right)){
            out.println("MSj验证Ui成功");
        }

        //MSJ向Ui发消息
        Element d=bp.getZr().newRandomElement().getImmutable();
        Element D=P.powZn(d).getImmutable();
        Element Tj=bp.getG1().newRandomElement().getImmutable();
        byte[] bh1j=sha1(Ui.toString()+MSj.toString()+A.toString()+D.toString()+ Tj.toString());
        Element k=bp.getZr().newElementFromHash(bh1j,0,bh1j.length).getImmutable();
        //MSj计算会话密钥,并将D M2 Tj发送给Ui
        byte[] bh3_ji=sha1(Ui.toString()+MSj.toString()+ A.powZn(k).add(Xi).powZn(d).toString()+Tj.toString());
        Element SK_ji=bp.getZr().newElementFromHash(bh3_ji,0,bh3_ji.length).getImmutable();
        byte[] bM3=sha1(Ui.toString()+MSj.toString()+ SK_ji.toString()+Tj.toString());
        Element M3=bp.getZr().newElementFromHash(bM3,0,bM3.length).getImmutable();
        //Ui do
        byte[] bh1j1=sha1(Ui.toString()+MSj.toString()+A.toString()+D.toString()+ Tj.toString());
        Element k1=bp.getZr().newElementFromHash(bh1j1,0,bh1j1.length).getImmutable();
        byte[] bh3_ij=sha1(Ui.toString()+MSj.toString()+ D.powZn(k1.mul(a).add(xi)).toString()+Tj.toString());
        Element SK_ij=bp.getZr().newElementFromHash(bh3_ij,0,bh3_ij.length).getImmutable();
        byte[] bM33=sha1(Ui.toString()+MSj.toString()+ SK_ij.toString()+Tj.toString());
        Element M33=bp.getZr().newElementFromHash(bM33,0,bM33.length).getImmutable();
        if(M3.isEqual(M33)){
            out.println("会话密钥协商成功");
        }
        skp.setProperty("SK_ji",SK_ji.toString());
        skp.setProperty("SK_ij",SK_ij.toString());
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
        String dir = "./storeFile/Ma13/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String verifyFileName=dir+"Veri.properties";
        String RC = "RC";
        String U_i="useri";
        String MS_j="MobileEdgeComputingServer";


        for (int i = 0; i < 10; i++) { //该方案无匿名性
            long start = System.currentTimeMillis();
            long start0 = System.currentTimeMillis();
            setup(pairingParametersFileName,publicParameterFileName,mskFileName,RC);
            long end0 = System.currentTimeMillis();
            System.out.println(end0 - start0);
            long start1 = System.currentTimeMillis();
            Registration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,RC,U_i);
            Registration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,RC,MS_j);
            long end1 = System.currentTimeMillis();
            System.out.println(end1 - start1);
            long start2 = System.currentTimeMillis();
            AKA(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,RC,U_i,MS_j);
            long end2= System.currentTimeMillis();
            System.out.println(end2 - start2);

            long end = System.currentTimeMillis();
            System.out.println(end - start+"total");
        }

    }
}
