package our;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static java.lang.System.out;

public class our {


    static Map<String, Element> map = new HashMap<>();

    public static void Setup(String pairingFile, String publicFile,String RC) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g2 = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("g1",g1.toString());//生成元
        PubProp.setProperty("g2",g2.toString());
        storePropToFile(PubProp,publicFile);

    }


    //用户和边缘服务器的注册阶段
    public static void KeyGen(String pairingFile,String publicFile,String pkFile,String skFile,int n,String User) throws NoSuchAlgorithmException {

        //获得系统参数
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String g1str=pubProp.getProperty("g1");
        String g2str=pubProp.getProperty("g2");
        Element g1 = bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //为用户(Ui or ES) 生成公私钥
        Element[] A = new Element[n];
        Element[][] B = new Element[n][2];
        for (int i = 0; i < n; i++) { //为A[]赋非零随机值
            Element random;
            do{
                random=bp.getZr().newRandomElement().getImmutable();
                if(random.isZero()){
                    continue;
                }
                break;
            }while(true);
            A[i]=random;
            skp.setProperty("A[]_"+i+User,Base64.getEncoder().encodeToString(A[i].toBytes()));//sk1
        }
        for(int i=0;i<n;i++){
            for(int j=0;j<2;j++){
                B[i][j]=bp.getZr().newRandomElement().getImmutable();
                skp.setProperty("B[][]_"+i+j+User,Base64.getEncoder().encodeToString(B[i][j].toBytes()));//sk2

            }
        }
        Element x1=bp.getZr().newZeroElement();
        Element x2=bp.getZr().newZeroElement();
        for(int i=0;i<n;i++){
            x1=A[i].mul(B[i][0]).getImmutable();
            x2=A[i].mul(B[i][1]).getImmutable();
        }
        skp.setProperty("x1_"+User,Base64.getEncoder().encodeToString(x1.toBytes()));//secret
        skp.setProperty("x2_"+User,Base64.getEncoder().encodeToString(x1.toBytes()));//secret
        Element pk=g1.powZn(x1).mul(g2.powZn(x2)).getImmutable();
        //map.put("pk"+User,pk);
        pkp.setProperty("pk_"+User,pk.toString());//pk

        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }



    //Ui和Sj的认证和密钥协商阶段
    public static void IdAuth(String pairingFile,String publicFile,String pkFile,String skFile,String veriFile,int n,String U_i,String S_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String g1str=pubProp.getProperty("g1");
        String g2str=pubProp.getProperty("g2");
        Element g1 = bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        //获取用户的公私钥
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        String pkUistr=pkp.getProperty("pk_"+U_i);
        //Element pkU_i=map.get("pk"+U_i);
        Element pkU_i=bp.getG1().newElementFromBytes(pkUistr.getBytes()).getImmutable();
        String pkSjstr=pkp.getProperty("pk_"+S_j);
                //map.get("pk"+S_j);
        Element pkS_j=bp.getG1().newElementFromBytes(pkSjstr.getBytes()).getImmutable();
        Element[] AU = new Element[n];
        for(int i=0;i<n;i++){
            String AUistr=skp.getProperty("A[]_"+i+U_i);
            AU[i]=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(AUistr)).getImmutable();
        }
        Element[][] BU = new Element[n][2];
        for(int i=0;i<n;i++) {
            for (int j = 0; j < 2; j++) {
                String BUistr = skp.getProperty("B[][]_" + i + j + U_i);
                BU[i][j] = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(BUistr)).getImmutable();
            }
        }
        Element[] AS = new Element[n];
        for(int i=0;i<n;i++){
            String ASjstr=skp.getProperty("A[]_"+i+S_j);
            AS[i]=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ASjstr)).getImmutable();
        }
        Element[][] BS = new Element[n][2];
        for(int i=0;i<n;i++) {
            for (int j = 0; j < 2; j++) {
                String BSjstr = skp.getProperty("B[][]_" + i + j + S_j);
                BS[i][j] = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(BSjstr)).getImmutable();
            }
        }

        //U_i do
        Element ID_U=bp.getZr().newElementFromBytes(U_i.getBytes()).getImmutable();//字符串转换为element,获取用户U的身份
        Element r1i=bp.getZr().newRandomElement().getImmutable();
        Element r2i=bp.getZr().newRandomElement().getImmutable();
        Element R1_i=g1.powZn(r1i).getImmutable();
        Element R2_i=g2.powZn(r2i).getImmutable();
        Element Ti=bp.getZr().newRandomElement().getImmutable();//时间戳

        //S_j收到（ID_U,R1_i,R2_i,Ti) then
        Element ID_S=bp.getZr().newElementFromBytes(U_i.getBytes()).getImmutable();
        Element r1j=bp.getZr().newRandomElement().getImmutable();
        Element r2j=bp.getZr().newRandomElement().getImmutable();
        Element R1_j=g1.powZn(r1j).getImmutable();
        Element R2_j=g2.powZn(r2j).getImmutable();
        Element cj=bp.getZr().newRandomElement().getImmutable();
        Element Tj=bp.getZr().newRandomElement().getImmutable();//时间戳

        //U_i收到（ID_S,R1_j,R2_j,cj,Tj) then
        Element ci=bp.getZr().newRandomElement().getImmutable();
        Element[] ABU1=new Element[n];
        Element[] ABU2=new Element[n];
        Element ABU1sum=bp.getZr().newZeroElement();
        Element ABU2sum=bp.getZr().newZeroElement();
        for(int i=0;i<n;i++){
            ABU1[i]=AU[i].mul(BU[i][0]).getImmutable();
            ABU1sum=ABU1sum.add(ABU1[i]);
            ABU2[i]=AU[i].mul(BU[i][1]).getImmutable();
            ABU2sum=ABU1sum.add(ABU2[i]);
        }
        Element v1i=r1i.add(cj.mul(ABU1sum)).getImmutable();
        Element v2i=r1i.add(cj.mul(ABU2sum)).getImmutable();

        //S_j收到（ID_U,v1i,v2i,ci,Ti') then
        Element left=g1.powZn(v1i).mul(g2.powZn(v2i)).getImmutable();
        Element right=R1_i.mul(R2_i).mul(pkU_i.powZn(cj)).getImmutable();
        if(left.isEqual(right)){
            out.println("sj验证ui成功");
        }
        else{
            out.println("sj验证ui失败");
        }

        Element[] ABS1=new Element[n];
        Element[] ABS2=new Element[n];
        Element ABS1sum=bp.getZr().newZeroElement();
        Element ABS2sum=bp.getZr().newZeroElement();
        for(int i=0;i<n;i++){
            ABS1[i]=AU[i].mul(BS[i][0]).getImmutable();
            ABS1sum=ABS1sum.add(ABS1[i]);
            ABS1[i]=AU[i].mul(BS[i][1]).getImmutable();
            ABS1sum=ABS1sum.add(ABS1[i]);
        }
        Element v1j=r1i.add(ci.mul(ABS1sum)).getImmutable();
        Element v2j=r1i.add(ci.mul(ABS2sum)).getImmutable();

        //U_i 收到（ID_S,v1j,v2j,cj,Tj') then
        Element left2=g1.powZn(v1j).mul(g2.powZn(v2j)).getImmutable();
        Element right2=R1_j.mul(R2_j).mul(pkS_j.powZn(ci)).getImmutable();
        if(left2.isEqual(right2)){
            out.println("ui验证sj成功");
        }
        else{
            out.println("ui验证sj失败");
        }
        //storePropToFile(verip,veriFile);

        //会话密钥协商
            //ui do
        byte[] bhU=sha1(ID_U.toString()+ID_S.toString()+ R1_j.powZn(r1i).toString()+R2_j.powZn(r2i).toString());
        Element SKey_U=bp.getZr().newElementFromHash(bhU,0,bhU.length).getImmutable();
        skp.setProperty("sessionkey_",SKey_U.toString());
        //U_i 运行密钥更新算法
            //sj do
        byte[] bhS=sha1(ID_U.toString()+ID_S.toString()+ R1_i.powZn(r1j).toString()+R2_i.powZn(r2j).toString());
        Element SKey_S=bp.getZr().newElementFromHash(bhS,0,bhS.length).getImmutable();
        skp.setProperty("sessionkey_",SKey_S.toString());
        //S_j 运行密钥更新算法
        storePropToFile(skp,skFile);
    }
    public static void KeyUpdate(String pairingFile,String publicFile,String pkFile,String skFile,int n,String User) throws NoSuchAlgorithmException {

        //获得系统参数
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String g1str=pubProp.getProperty("g1");
        String g2str=pubProp.getProperty("g2");
        Element g1 = bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);
        //获取用户的私钥
        Element[] AUser = new Element[n];
        for(int i=0;i<n;i++){
            String AUserstr=skp.getProperty("A[]_"+i+User);
            AUser[i]=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(AUserstr)).getImmutable();
        }
        Element[][] BUser = new Element[n][2];
        for(int i=0;i<n;i++) {
            for (int j = 0; j < 2; j++) {
                String BUserstr = skp.getProperty("B[][]_" + i + j + User);
                BUser[i][j] = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(BUserstr)).getImmutable();
            }
        }


        //为用户(Ui or ES) 更新私钥
        Element[] A1 = new Element[n];
        Element[][] B1 = new Element[n][2];
        Element[] E = new Element[n];
        Element[][] F = new Element[n][2];
        Element[][] T = new Element[n][n];
        //初始化E F T
        for (int i = 0; i < n; i++) {

            E[i] = bp.getZr().newRandomElement().getImmutable();
            F[i][0] = bp.getZr().newRandomElement().getImmutable();
            F[i][1] = bp.getZr().newRandomElement().getImmutable();
            B1[i][0] = bp.getZr().newRandomElement().getImmutable();
            B1[i][1] = bp.getZr().newRandomElement().getImmutable();
            for (int j = 0; j < n; j++) {
                T[i][j] = bp.getZr().newRandomElement().getImmutable();
            }
        }
        Element[] E1 = new Element[n];
        Element[][] F1 = new Element[n][2];
        Element[][] T1 = new Element[n][n];
        //初始化E1 F1 T1
        for (int i = 0; i < n; i++) {

            E1[i] = bp.getZr().newRandomElement().getImmutable();
            F1[i][0] = bp.getZr().newRandomElement().getImmutable();
            F1[i][1] = bp.getZr().newRandomElement().getImmutable();
            for (int j = 0; j < n; j++) {
                T1[i][j] = bp.getZr().newRandomElement().getImmutable();
            }
        }

        //限制条件
        Element[] E_mul_F = new Element[2]; // 结果是一个1x2矩阵，用长度为2的数组表示
        Element EF=bp.getZr().newZeroElement();
        //1.check E·F=（0，0）?
        for (int j = 0; j < 2; j++) { // 遍历F的列
            Element sum = bp.getZr().newZeroElement();
            for (int i = 0; i < n; i++) { // 遍历E的行（实际上只有一行，这里遍历E的元素）
                sum = sum.add(E[i].mul(F[i][j]));
            }
            E_mul_F[j] = sum.getImmutable();
            EF=EF.add(E_mul_F[j]).getImmutable();
        }
        //2.check A·T=E ?
        //计算A·T
        Element[] AT = new Element[n];
        for (int i = 0; i < n; i++) {
            Element sum = bp.getZr().newZeroElement();
            for (int j = 0; j < n; j++) {
                sum = sum.add(AUser[j].mul(T[j][i])); // 注意这里 T 的索引是 [j][i]，因为 T 是 nxn 而 A 是 1xn
            }
            AT[i] = sum.getImmutable();
        }
        // 检查 A·T是否等于E
        boolean Equal = true;
        for (int i = 0; i < n; i++) {
            if (!AT[i].isEqual(E[i])) {
                Equal = false;
                break;
            }
        }
        Element zero=bp.getZr().newZeroElement().getImmutable();
        if (EF.isEqual(zero) && Equal) { //满足限制条件的前提下，更新私钥中的B为B1(B')
            // 计算B1=B+T·F
            for (int i = 0; i < n; i++) { // 遍历B1的行（也是T的行）
                for (int j = 0; j < 2; j++) { // 遍历B1的列（也是F的列）
                    Element sum = bp.getZr().newZeroElement();
                    for (int k = 0; k < n; k++) { // 遍历T的列和F的行（因为它们是相乘的）
                        sum = sum.add(T[i][k].mul(F[k][j])); // T的第i行与F的第j列的点积
                    }
                    B1[i][j] = BUser[i][j].add(sum).getImmutable();
                    skp.setProperty("B1[n][2]_"+i+j+User,Base64.getEncoder().encodeToString(B1[i][j].toBytes()));//secret
                }
            }
            //System.out.println("A * T 等于 E");
        }
        Element[] E1_mul_F1 = new Element[2]; // 结果是一个1x2矩阵，用长度为2的数组表示
        Element EF1=bp.getZr().newZeroElement();
        //3.check E1·F1=（0，0）?
        for (int j = 0; j < 2; j++) { // 遍历F的列
            Element sum1 = bp.getZr().newZeroElement();
            for (int i = 0; i < n; i++) { // 遍历E的行（实际上只有一行，这里遍历E的元素）
                sum1 = sum1.add(E[i].mul(F[i][j]));
            }
            E1_mul_F1[j] = sum1.getImmutable();
            EF1=EF1.add(E1_mul_F1[j]).getImmutable();
        }
        //4.check T1·B1=F1 ?
        //计算T1·B1
        Element[][] T1B1 = new Element[n][2];
        for (int i = 0; i < n; i++) { // 遍历T1B1的行（也是T1的行）
            for (int j = 0; j < 2; j++) { // 遍历T1B1的列（也是B1的列）
                Element sum3 = bp.getZr().newZeroElement();
                for (int k = 0; k < n; k++) { // 遍历T1的列和B1的行（因为它们是相乘的）
                    sum3 = sum3.add(T1[i][k].mul(B1[k][j])); // T1的第i行与B1的第j列的点积
                }
                T1B1[i][j] = sum3.getImmutable();
            }
        }
        boolean Equal1 = true;
        Element[][] F10 = new Element[n][2];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < 2; j++) {
                if (!T1B1[i][j].isEqual(F10[i][j])) {
                    Equal1 = false;
                    break;
                }
            }
        }
        if(Equal1&&EF1.isEqual(zero)){
            // 计算A1=A+E1·T1
            for (int i = 0; i < n; i++) {
                Element sum4 = bp.getZr().newZeroElement();
                for (int j = 0; j < 2; j++) {
                        sum4 = sum4.add(T1[i][j].mul(T1[j][i]));

                }
                A1[i] = AUser[i].add(sum4).getImmutable();
                skp.setProperty("A1[n]_"+i+User,Base64.getEncoder().encodeToString(A1[i].toBytes()));//secret
            }
        }

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
        int n=10;//矩阵的维度
        /*
        指定配置文件的路径
         */
        String dir = "./storeFile/our/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String certificateFileName=dir+"certi.properties";
        String verifyFileName=dir+"Veri.properties";
        String RC = "RC";
        String U_i="User";
        String S_j="ES";


        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            Setup(pairingParametersFileName,publicParameterFileName,RC);
            KeyGen(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,n,U_i);
            KeyGen(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,n,S_j);
            IdAuth(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,verifyFileName,n,U_i,S_j);
            //密钥更新 连续抗泄露
            KeyUpdate(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,n,U_i);
            KeyUpdate(pairingParametersFileName,publicParameterFileName,publicKeyFileName,secretKeyFileName,n,S_j);
            long end = System.currentTimeMillis();
            System.out.println(end - start);
        }


    }
}
