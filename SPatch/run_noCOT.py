from ollama import chat
from ollama import ChatResponse
import os
folder_path = "/root/SPatchD/nsp/"

Prompt='''
请判断补丁是安全补丁还是非安全补丁
输出：SP或者NSP
'''
n=0
# 遍历文件夹中的所有文件
for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    
    # 只处理文件
    if os.path.isfile(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
             #code = file.read()
            lines = file.readlines()

            # 从 diff 开始的部分提取内容
            diff_started = False
            code = ""
            
            for line in lines:
                if line.startswith("diff"):  # 标识 diff 开始
                    diff_started = True
                if diff_started:  # 只读取 diff 之后的部分
                    code += line
            print(n)
            print()
            n=n+1
            # 构建 prompt
            prompt = f"{Prompt}\nDiff: {code}"
            
            # 与Chat模型进行交互
            response = chat(
                model='deepseek-R1:70b', 
                messages=[{'role':'user', 'content': prompt}],
                stream=False,
                options={'temperature': 0.7}
            )
            
            # 打印响应内容
            print(f"Response for {filename}:")
            context_A = response['message']['content']
            context_A_1 = context_A[context_A.index('</think>')+len('</think>')+1:]
            print(context_A_1)
