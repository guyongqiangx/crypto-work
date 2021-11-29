- ASN.1概述及数据类型详解
  - https://blog.csdn.net/qq_33336155/article/details/54563449

[TOC]

## 1. ASN.1语法

ASN.1语法遵循传统的巴科斯范式 BNF 风格.

最基本的表达式如: `Name ::= type`. 表示为定义某个名称为 Name 的元素，它的类型为 type.

例如:`MyName ::= IA5String`. 表示为定义了一个名为 MyName 的元素或变量，其类型为 ASN.1 类型 IA5String (类似于ASCII字符串).

### 1.1 ASN.1显式值(Explict Value)

有些时候，我们需要定义一种ASN.1类型，它的子集元素包含预定义值．

`Name ::= type(Explict Value)`

显式值(ExplictValue)．必须是ASN.1类型允许选择的值，而且也必须是元素所允许的值．例： `MyName ::=IA5String(Tom)` 表示 MyName 是字符串 Tom 的IA5String 编码．又例如：`MyName ::= IA5String(Tom|Joe)` 表示字符串的值既可以是Tom, 也可以是Joe.

这种语法的使用是为了扩展确定的解码器．例：
```
PublicKey::= SEQUENCE {undefined
    KeyType     BOOLEAN(0),
    Modulus     INTEGER,
    PubExponent INTEGER
}

PrivateKey ::= SEQUENCE {undefined
    KeyType         BOOLEAN(1)
    Modulus         INTEGER,
    PubExponent     INTEGER,
    PrivateExponent INTEGER
}
```

### 1.2 ASN.1容器(Container)

容器是值一个包含了其他相同或者不同类型元素的数据类型（例如序列值 SEQUENCE 或集合值 SET 类型）．目的是为了组合一些复杂的数据类型集．ASN.1规范定义了4种容器类型：序列，单一序列(SEQUENCE OF)，集合和单一集合(SET OF)．虽然它们意义不同，但是语法是一样的．

`Name ::= Container {Name Type [ Name Type...]}`

方括号中的内容和容器的元素个数都是可选项．还可以进行嵌套定义．例：
```
UserRecord::= SEQUENCE {undefined
    Name    SEQUENCE {undefined
        First IA5String,
        Last  IA5String
    },
    DoB     UTCTIME
}
```

将其粗略的翻译成Ｃ语言中的结构如下：
```
structUserRecord {undefined
    struct Name {undefined
        char *First,
        char *Last
    };
    time_t DoB;
}
```

### 1.3 ASN.1 修改器

ASN.1定义了各种修改器，如可选(OPTIONAL),默认(DEFAULT),和选择(CHOICE). 他们可以改变表达式的声明．典型地用于定义一种要求编码灵活，而定义又不繁琐的类型．

#### ＜１＞．可选(OPTIONAL)

顾名思义，其表示改变一个元素以便在编码时它的类型是可选择的．即编码器可以忽略这个元素，解码器不能假设它将出现．但当邻接的两个元素具有相同的类型时，会给解码器带来一些问题．

定义： `Name ::= Type OPTIONAL`

例如：
```
Float::= SEQUENCE {undefined
    Exponent    INTEGER OPTIONAL,
    Mantissa    INTEGER,
    Sign        BOOLEAN
}
```
当解码器读取这个结构时，在它看来第一个整数(INTEGER)可能是 Exponent,也有可能认为是 Mantissa．
一般建议不使用这种方式定义结构．

#### ＜２＞．默认(DEFAULT)

默认修改器允许容器包含默认值．如果待编码的数据值等同于它的默认值，那么它将在发送的数据流中被忽略．例如：
```
Command::= SEQUENCE {undefined
    Token         IA5String(NOP) DEFAULT,
    Parameter   INTEGER
}
```

如果编码器把Token看成是代表字符串NOP,那么序列将按照定义的那样编码为：
```
Command ::= SEQUENCE {undefined
    Parameter    INTEGER
}
```

#### ＜３＞．选择(CHOICE)

选择修改器允许一个元素在给定的实例中可以有多个可能值．实质上说，解码器将尝试所有期望的解码算法，直到有一个类型符合为止．当一个复杂的容器中包含其他容器时，时候选择器就十分有用了．例如：
```
UserKey::= SEQUENCE {undefined
    Name        IA5String,
    StartDate   UTCTIME,
    Expire      UTCTIME,
    KeyData     CHOICE {undefined
        ECCKey      ECCKeyType,
        RSAKey      RSAKeyType
    }
}
```
上例简单的允许 ECC 也允许 RSA 密钥的公钥证书．

## 2. ASN.1 数据类型

任何ASN.1编码都是以两个字节开始（或者八位位组，含有８个二进制位），不管什么类型，它们都是通用的．第一个字节是类型标识符，也包含一些修正位；第二各字节是长度．

![image.png](https://note.youdao.com/yws/res/0/WEBRESOURCEfcd7a2196088398c99673821933a21e0)

### 2.1 ASN.1 布尔类型(0x01)

布尔编码的负载或者是全0或者是全1的八位位组。头字节以0x01开始，长度编码字节为0x01,负载内容取决于布尔值的取值。
```
False [00000000-0x00]: 01 01 00
 True [11111111-0xFF]: 01 01 FF
```

### 2.2 ASN.1 整数(0x02)

整数类型表示一个有符号的任意精度的标量，它的编码是可移植，平台无关的。

正整数的编码比较简单。每个字节表示的最大整数是255 (0xFF), 存储的实际数值分成字节大小的数字，并且以big-endian格式存储。

八位位组{Xk,Xk-1,...., X0}将以递减的顺序从Xk到X0进行存储．编码规定正整数的第一个字节的最高位必须是0,即Xk的最高为必须是0，为1的话则为负数．例如：　x = 49468= 193 * 256 + 60 = 0xC1 * 0x FF + 0x3C; 即X1=0xC1, X0= 0x3C. 按正常规定，编码应该是 0x02 02 C1 3C, 但是X1的最高位是1, 应该被看成负数．最简单的方法是用前端零字节进行填充．编码变为 0x02 02 00 C1 3C．

负整数的编码有些复杂．要先找到一个最小的256的幂，使它比要编码的负数的绝对值还要大．例如：x = - 1555; 被1555大的256的最小的幂是256^2 = 65536; 然后将这个数跟负数相加以得到2的补码． 65536 + (-1555) = 63981 =  0xF9 * 0xFF + 0x ED. 则编码为 0x02 02F9 ED.

以下是一些常用整数编码的例子:

```
         0 [      0x00]: 02 01 00
         1 [      0x01]: 02 01 01
         2 [      0x02]: 02 01 02
       127 [      0x7F]: 02 01 7F
       128 [      0x80]: 02 02 00 80
        -1 [         ?]: 02 01 FF
      -128 [         ?]: 02 01 80
    -32768 [         ?]: 02 02 80 00
1234567890 [0x499602D2]: 02 04 49 96 02 D2
```

### 2.3 ANS.1 位串类型(0x03)

位串(BITSTRING)类型以可移植形式表示位数组．除了ASN.1头部两个字节之外，还有一个附加的头部用来表示填充数据(通常是一个字节,因为填充是为了形成一个完整的字节)．

编码规则：位串的第一位放到第一个负载字节的第8位；位串的第二位放到第一个负载字节的第7位; 依此类推．填充满第一个负载字节，就继续填充第二个负载字节．如果最后一个负载字节未被填充满，空的位用0来填充, 0的个数存放到头部用来表示填充数据的那个字节里．

下面举例说明：

有一个位串`{1,0,0,0,1,1,1,0,1,0,0,1}`，开始填充负载字节．第一个字节填充后为`10001110 = 0x8E`; 第二个字节填充后为`10010000 = 0x90`, 低位4个0为填充的空位．则，负载为2个字节加上表示填充0个数的一个字节0x04总共3个字节．则完整的编码为：`0x03 03 04 8E 90`.

```
1,0,0,0,1,1,1,0,1,0,0,1: (1,0,0,0,1,1,1,0) -> 0x8E, (1,0,0,1_0_0_0_0) -> 0x90

padding 0 count: {0x04}
           data: {0x8E, 0x90}
         length: {0x03}
           type: {0x03}
     Bit String: 03 03 04 8E 90
```

解码器通过计算 8 * 负载长度 - 填充数来得到存储输出所需要的位数．

### 2.4 ASN.1 八位位组串(Octets String)(0x04)

八位位组串(OCTET STRING)是保存字节数组，它和位串类型(BIT STRING)很相似．这种编码非常简单，像其他类型一样对头部进行编码，然后直接将八位位组复制过去即可．例如：对`{FE, ED, 6A, B4}`编码；首先存储类型`0x04`, 接着是长度`0x04`,然后是字节本身`0xFE ED 6A B4`; 完整的编码为`0x04 04 FE ED 6A B4`.

```
Octets String in ASN.1:
         data: {0xDB, 0xFE, 0xED, 0x6A, 0xB4};
       length: {0x05}, 5 bytes;
         type: {0x04}, octets string;
Octets String: 04 05 DB FE ED 6A B4
```

### 2.5 ASN.1 空类型(0x05)

空(NULL)类型实际上是"占位符", 它是含有空白选项的选择修改器所特有．例如：
```
MyAccount ::= SEQUENCE {undefined
    Name        IA5String,
    Group       IA5String,
    Credentials CHOICE{undefined
        rsaKey      RSAPublicKey,
        passwdHash  OCTET STRING,
        none        NULL
    }
}
```

在上面这个结构中，帐号的证书应该包含一个 RSA 密钥或一个密码散列值或什么都没有．

空类型的编码是 `05 00`.

```
  type: {0x05}
length: {0x00}
  Null: 05 00
```

### 2.6 ASN.1 对象标识符类型(0x06)

对象标识符(OBJECTIDENTIFIER, OID)类型用层次的形式来表示标准规范．标识符树通过一个点分的十进制符号来定义，这个符号以组织，子部分然后是标准的类型和各自的子标识符开始．

例如：MD5 的 OID 是`1.2.840.113549.2.5`  表示为"`iso(1) member-body (2) US (840) rsadsi(113549) digestAlgorithm(2) md5 (5)`", 所以当解码程序看到这个 OID 时,就知道是 MD5 散列.

OID 在公钥算法标准中很流行,它指出证书绑定了哪种散列算法. 同样,也有公钥算法,分组算法,和操作模式的 OID. 它们是一种高效且可移植的表示数据包中所选算法的形式.

对OID的编码规则:

前两部分如果定义为 x.y, 那么它们将合成一个字 40*x + y, 其余部分单独作为一个字节进行编码.

每个字首先被分割为最少数量的没有头零数字的7位数字.这些数字以big-endian格式进行组织,并且一个接一个地组合成字节. 除了编码的最后一个字节外,其他所有字节的最高位(位8)都为1.

> 相当于:
> $$A\ =\ X_n*128^n + X_{n-1}*128^{n-1} + ... + X_2*128^2 + X_1*128^1 + X_0$$

举例: $$30331 = 1*128^2 + 108*128^1 + 123$$

因此: `30331 = 1 * 128^2 + 108 * 128 + 123` 分割成7位数字(0x80)后为`{1,108,123}`设置最高位后变成`{129,236,123}`(即: `129=1|0x80, 236=108|0x80, 123`). 如果该字只有一个7位数字,那么最高为0.

MD5 OID 的编码:
1. 将 `1.2.840.113549.2.5` 转换成字数组 `{42, 840, 113549, 2, 5}`.
2. 然后将每个字分割为带有最高位的7位数字，`{undefined{0x2A},{0x86,0x48},{0x86,0xF7,0x0D},{0x02},{0x05}}`.
3. 最后完整的编码为 `06 08 2A 86 48 86 F7 0D 02 05`.

```
{1.2.840.113549.2.5} --> {42=40*1+2,       840,         113549,    2,    5} /* 转换前两部分 */
                     --> {     0x2A, 0x86-0x48, 0x86-0xF7-0x0D, 0x02, 0x05} /* 分割成 7 位数字编码 */
  type: {0x06}
length: {0x08}
  data: {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05}
   OID: 06 08 2A 86 48 86 F7 0D 02 05
```

### 2.7 ASN.1 序列(0x30)和集合类型

序列(SEQUENCE)和单一序列(SEQUENCE OF)以及相应的集合(SET)和单一集合(SET OF)类型叫做"结构"类型或简单容器．它们是一种用来把相关数据元素收集为一个独立的可解码元素的简单方法．

序列编码有以下性质：
1. 编码是结构化的．即头字节的位6必须设置．　
2. 编码的内容是由 ASN.1 序列类型定义列表中的所有数据类型值的完全编码所组成，并且按照它们出现的顺序进行编码，除非这些类型被可选(OPTIONAL)或默认(DEFAULT)关键字所引用．

例：考虑如下序列
```
User ::== SEQUENCE{undefined
ID        INTEGER,
Active BOOLEAN
}
```

当取值为{32, TRUE}时，编码为 {0x30 06 02 01 20 01 01 FF} 在ASN.1文档里，使用空格来表示编码的属性．
```
30 06
      02 01 20
      01 01 FF

    type: {0x30}
  length: {0x06}
    data: {0x02, 0x01, 0x20, 0x01, 0x01, 0xFF}
Sequence: 30 06 02 01 20 01 01 FF
```

### 2.8 ASN.1 可打印字符串(0x13)和IA5String类型(0x16)

可打印字符串(PrintableString)和 IA5String 类型定义了一种独立于本地代码页和字符集定义，在任何平台上都可以将 ASCII 字符串编码为可读字符串的可移植方法．

可打印字符串对象是 ASCII 集合的一个有限子集，这个子集包括 32,39,40~41,43~58,61,63以及65~122.

IA5String 类型的编码对象是 ASCII 集合中的大多数．包括 NULL,BEL,TAB,NL,LF,CR以及32~126.

可打印字符串和 IA5String 的编码和八位位组串相似．可打印字符串的头字节是0x13, IA5String的是0x16. 例如："Hello World"的编码为:
```
Hello World: 13 0B 48 65 6D 6D 6F 20 57 6F 72 6D 64.

  type: {0x13}
length: {0x0B}
  data: {0x48, 0x65, 0x6D, 0x6D, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6D, 0x64} /* "Hello World" */
String: 13 0B 48 65 6D 6D 6F 20 57 6F 72 6D 64
```

### 2.9 ASN.1世界协调时类型(0x17)

世界协调时(UTCTIME)定义了一种相对 GMT 时间的标准时间(以日期)编码.它使用"YYMMDDHHMMSSZ"的格式分别表示年,月,日,时,分,秒. 其中"Z"是遗留自初始的UTCTIME.如果没有"Z",就允许两种附加组"[+/-]hh 'mm'",其中"hh"和"mm"分别为与GMT的时差和分差. 如果有"Z",则时间是以Zulu或GMT时间表示.

字符串的编码按照 IA5String 编码规则进行转换(ASCII字符集),其头字节为 0x17 而不是 0x16. 例如:
```
July 4,2003 at 11:33 and 28 seconds
```
编码为:
```
030704113328Z
```
再编码:
```
17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A

  type: {0x17}
length: {0x0D}
  data: {0x30, 0x33, 0x30, 0x37, 0x30, 0x34, 0x31, 0x31, 0x33, 0x33, 0x32, 0x38, 0x5A} /* "030704113328Z" --> "July 4,2003 at 11:33 and 28 seconds" */
   UTC: 17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A
```
