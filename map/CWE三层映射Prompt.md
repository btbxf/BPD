#  Prompt   
## 组分类
你是漏洞分析专家请按依次完成下述内容。
1. 补丁修复了下面哪种类型的漏洞？
2. 请输出Top3种可能
输出格式：
-类型:置信度分数
-类型:置信度分数
-类型:置信度分数
```
### **1.输入验证与注入类问题****共性**:这些弱点都与输入的验证、输出的编码或逃逸相关，可能导致注入攻击(如命令执行、SQL注入等)。
### **2.内存管理类问题****共性**:与内存缓冲区操作不当有关，可能导致缓冲区溢出或其他内存相关漏洞。
### **3.信息泄露与敏感数据保护类问题****共性**:这些弱点都与敏感信息的泄露或加密机制的不足有关，可能导致数据被窃取或解密 。
### **4.认证与授权类问题****共性**:这些弱点都与身份验证、权限管理或授权机制的不足有关，可能导致未经授权的访问。
### **5.资源管理类问题****共性**:这些弱点都与资源的管理、同步或释放相关，可能导致资源泄漏、竞态条件或性能问题。
### **6.算法设计与复杂度类问题****共性**:这些弱点都与资源的管理、同步或释放相关，可能导致资源泄漏、竞态条件或性能问题。
### **7.数据处理与类型转换类问题****共性**:这些弱点都与数据处理、类型转换或对象引用的错误有关，可能导致逻辑错误或安全漏洞。
### **8.其他(无明显关联的弱点)****共性**:这些弱点虽然没有明显的直接关联，但都涉及资源管理、同步或数据存储中的错误，可能导致安全漏洞。
```

## 父类型分类
你是漏洞分析专家
1. 你如何区分下面几种类型？
{分别推理Top3组的类型}
```例
CWE-290 - Base Authentication Bypass by Spoofing
CWE-294 - Base Authentication Bypass by Capture-replay
CWE-295 - Base Improper Certificate Validation
CWE-306 - Base Missing Authentication for Critical Function
CWE-307 - Base Improper Restriction of Excessive Authentication Attempts
CWE-521 - Base Weak Password Requirements
CWE-425 Base Direct Request ('Forced Browsing')
```
3. 请分析diff可能修复了哪几种漏洞类型，并计算置信度
4. 请输出Top3种可能
输出格式：
-CWE-ID name:置信度分数
-CWE-ID name:置信度分数
-CWE-ID name:置信度分数

## 子类型分类
你是漏洞分析专家
1. 请分析diff可能修复了下面哪几种漏洞类型，并计算置信度
{分别推理Top3父类型的子类}
```例
CWE-290 - Base Authentication Bypass by Spoofing
CWE-294 - Base Authentication Bypass by Capture-replay
CWE-295 - Base Improper Certificate Validation
CWE-306 - Base Missing Authentication for Critical Function
CWE-307 - Base Improper Restriction of Excessive Authentication Attempts
CWE-521 - Base Weak Password Requirements
CWE-425 Base Direct Request ('Forced Browsing')
```
3. 请输出Top3种可能
输出格式：
-CWE-ID name:置信度分数
-CWE-ID name:置信度分数
-CWE-ID name:置信度分数
