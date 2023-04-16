import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

public class RSA {
    //公钥 e
    private static BigInteger publicKeyE;
    //公钥 n
    private static BigInteger publicKeyN;
    //私钥 d
    private static BigInteger privateKeyD;
    //大素数 p
    private static BigInteger p;
    //大素数 q
    private static BigInteger q;
    //Fn
    private static BigInteger fn;
    private static int messagelength;
    private static int bytes;


    public static void main(String[] args) {
        String s1 = "真的猛士，敢于直面惨淡的人生，敢于正视淋漓的鲜血。这是怎样的哀痛者和幸福者？然而造化又常常为庸人设计，以时间的流驶，来洗涤旧迹，仅使留下淡红的血色和微漠的悲哀。在这淡红的血色和微漠的悲哀中，又给人暂得偷生，维持着似人非人的生活。我不知道这样的世界何时是一个尽头！";   // 明文
        p = BigInteger.probablePrime(400,new Random());  // 获取随机大素数p
        q = BigInteger.probablePrime(400,new Random());  // 获取随机大素数p
//        System.out.println(p.toString().length());
        getPublicKeyN();
        getPublicKeyE();
        getPrivateKeyD();
        getDealBytes(publicKeyN);
//        System.out.println(bytes);
        System.out.println("公钥n:\n"+publicKeyN);
        System.out.println("公钥e:\n"+publicKeyE);
        System.out.println("私钥d:\n"+privateKeyD);
        String ciphertext = encrypt(s1);
        System.out.println("密文：\n"+ciphertext);

        String resultText = decrypt(ciphertext);
        System.out.println("明文：\n"+resultText);
    }

    // 加密
    public static String encrypt(String plaintext) {
        List<BigInteger> list = encodeMessage(plaintext, publicKeyE, publicKeyN);
        String encodeMessage = "";
        for (BigInteger m : list) {
            encodeMessage += m.toString() + " ";
        }
//        System.out.println("密文：\n" + encodeMessage);

        byte[] encodeBase64 = Base64.getEncoder().encode(encodeMessage.getBytes());
        //        System.out.println("编码后密文：\n"+encodeBase64Str);
        return new String(encodeBase64);
    }

    // 解密
    public static String decrypt(String ciphertext) {
        byte[] decodeBase64Byte = Base64.getDecoder().decode(ciphertext);
        String decodeBase64Str = new String(decodeBase64Byte);
//        System.out.println("解码后密文：\n"+decodeBase64Str);

        String[] decodeSplit = decodeBase64Str.split(" ");
        List<BigInteger> decodeBase64List = new ArrayList<>();
        for (String b : decodeSplit) {
            decodeBase64List.add((new BigInteger(b)));
        }
        //将密文进行解密
        //        System.out.println("解密结果：\n" + decodeMessage);
        return decodeMessage(decodeBase64List, privateKeyD, publicKeyN);
    }

    // 获取公钥n和欧拉函数值
    public static void getPublicKeyN(){
        publicKeyN = p.multiply(q);
        fn = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    // 获取公钥e
    public static void getPublicKeyE(){
        publicKeyE = BigInteger.TWO;
        while (true){
            if(publicKeyE.gcd(fn).compareTo(BigInteger.ONE) == 0 && publicKeyE.compareTo(fn) == -1){
                break;
            }
            publicKeyE = publicKeyE.add(BigInteger.ONE);
        }
    }

    // 获取私钥d
    public static void getPrivateKeyD(){
        BigInteger k = BigInteger.ONE;
        while(true){
            if(fn.multiply(k).add(BigInteger.ONE).mod(publicKeyE).compareTo(BigInteger.ZERO) == 0){
                privateKeyD = fn.multiply(k).add(BigInteger.ONE).divide(publicKeyE);
                break;
            }
            k = k.add(BigInteger.ONE);
        }
    }

    // 获取每次加密的字符数
    public static void getDealBytes(BigInteger publicKeyN) {
        for (int i=1;;i++){
            if(publicKeyN.shiftRight(7*i).compareTo(BigInteger.ZERO) == 1){
                bytes = i;
            }else {
                break;
            }
        }
    }

    // 快速幂
    public static BigInteger qpow(BigInteger a,BigInteger n,BigInteger mod){
        BigInteger ans = BigInteger.ONE;
        while(n.compareTo(BigInteger.ZERO) != 0){
            if(n.and(BigInteger.ONE).compareTo(BigInteger.ZERO) != 0){
                ans = ans.multiply(a).mod(mod);
            }
            a = a.multiply(a).mod(mod);
            n = n.shiftRight(1);
        }
        return ans.mod(mod);
    }

    // 对明文加密
    public static String encode(BigInteger plainText, BigInteger publicKeyE, BigInteger publicKeyN){
        BigInteger C = qpow(plainText,publicKeyE,publicKeyN);
        return C.toString();
    }

    // 对字符串加密
    public static List<BigInteger> encodeMessage(String code, BigInteger publicKeyE, BigInteger publicKeyN){
        //先对字符串进行编码,防止有中文
        byte[] codeBase64 = Base64.getEncoder().encode(code.getBytes());
        code = new String(codeBase64);

        messagelength = code.length();
        char[] message = code.toCharArray();
        List<BigInteger> result = new ArrayList<>();

        int i, j;
        BigInteger x;

        for(i = 0; i < message.length; i+=bytes) {
            x = BigInteger.ZERO;
            for (j = 0; j < bytes && (i+j) < message.length; j++){
                BigInteger tmp = BigInteger.ONE;
                x = x.add(tmp.shiftLeft(7*j).multiply(BigInteger.valueOf(message[i + j])));
            }
            // 对转换出来的数字进行加密
            String encode = encode(x, publicKeyE, publicKeyN);
            result.add(new BigInteger(encode));
        }
        return result;
    }

    // 对密文解密
    public static String decode(BigInteger C, BigInteger privateKeyD, BigInteger publicKeyN){
        BigInteger m = qpow(C,privateKeyD,publicKeyN);
        return  m.toString();
    }

    // 对字符串解密
    public static String decodeMessage(List<BigInteger> encode, BigInteger privateKeyD, BigInteger publicKeyN){

        String decode = "";
        String x;
        for (int i = 0; i < encode.size(); i++) {
            x = decode(encode.get(i), privateKeyD, publicKeyN);

            int count = bytes;
            // 判断最后一个密文加密时被一次处理了几个字符个数是否是bytes的整数倍
            if (i == encode.size()-1){

                if (messagelength % bytes != 0){
                    count = messagelength % bytes;
                }
            }
            for (int j = 0; j < count; j++) {
                BigInteger temp = new BigInteger(x);
                BigInteger mod = temp.shiftRight(7 * j).mod(new BigInteger("128"));
                decode += (char) Integer.parseInt(mod.toString());
            }
        }
        //对解密出来的字符串进行中文解码
        byte[] bytes = Base64.getDecoder().decode(decode);
        decode = new String(bytes);
        return decode;
    }
}
