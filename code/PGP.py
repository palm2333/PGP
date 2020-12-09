# -*- coding: utf-8 -*-
"""
Created on Sat Nov 14 12:35:26 2020

@author: xyy13
"""
import myRSA
import zip_unzip
import myIDEA
import base64
from md5 import MD5
import time

def receiver_rsa_key():
    max_k=65535
    receiver_rsa_n,receiver_rsa_e,receiver_rsa_d=myRSA.rsa_key(max_k)
    return receiver_rsa_n,receiver_rsa_e,receiver_rsa_d

#发送者
def deliver(file,receiver_rsa_n,receiver_rsa_e): 
    #MD5处理生成MD5(M)    
    f=open(file,'r')
    string=f.read()
    f.close()
    md5_cipher=MD5.hash(string)  
    print("md5_cipher:",md5_cipher)
    
    #发送者RSA私钥对MD5(M)加密，得到签名S
    #生成RSA密钥对
    deliver_rsa_n,deliver_rsa_e,deliver_rsa_d=myRSA.rsa_key(md5_cipher)
    #rsa私钥加密
    deliver_rsa_cipher=myRSA.rsa_encrypt(md5_cipher,deliver_rsa_d,deliver_rsa_n)
    print("deliver signature S:",deliver_rsa_cipher)
    
    #<M,S>写入file_path，最后一行为签名
    f=open(file,'a')
    signature='\n'+str(deliver_rsa_cipher)
    f.write(signature)
    f.close()
    
    #zip压缩<M,S>,得到zip(<M,S>)，保存在message.zlib.txt中
    zip_file = "message.zlib.txt"
    zip_unzip.compress(file, zip_file)
  
    #IDEA加密zip(<M,S>)得到IDEA(zip(<M,S>))
    f=open(zip_file,'rb')
    zip_message=f.read()
    f.close()
    idea_cipher,idea_k,idea_n,idea_r=myIDEA.IDEA_encrypt(zip_message)    
    #写入最后发送的文件final.txt
    final_file="final.txt"
    f=open(final_file,'wb')
    f.write(idea_cipher)
    f.close()   
    
    #接收者的RSA公钥对IDEA的密钥加密生成rsa_idea_k，追加写入final.txt中
    rsa_idea_k=[]
    f=open(final_file,'a')
    for key in idea_k:
        tmp=myRSA.rsa_encrypt(key,receiver_rsa_e,receiver_rsa_n)
        rsa_idea_k.append(tmp)
        f.write('\n'+str(tmp))
    f.close()
    
    #base64编码，变成ascii码保存在final.txt中
    f=open(final_file,'rb')
    final_message=f.read()
    f.close()
    final_message=base64.b64encode(final_message)
    f=open(final_file,'wb')
    f.write(final_message)
    f.close()

    return final_file,idea_n,idea_r,deliver_rsa_n,deliver_rsa_e

#接收者
def receiver(final_file,receiver_rsa_n,receiver_rsa_d,idea_n,idea_r,deliver_rsa_n,deliver_rsa_e):
    #base64解码得到final_message，写入final_file
    f=open(final_file,'rb')
    final_message=f.read()
    f.close()
    final_message=base64.b64decode(final_message)
    f=open(final_file,'wb')
    f.write(final_message)
    f.close()
    
    #切片final_message得到idea_cipher即IDEA(zip(<M,S>))和rsa_idea_k
    tmp=str(final_message)
    tmp=tmp[2:-1]   
    tmp=tmp.split('\\r\\n')
    idea_cipher=''
    rsa_idea_k=[]
    count=0#记录rsa_idea_k占多少位
    for i in range(52):
        rsa_idea_k.append(int(tmp[-52+i]))      
        count+=len(tmp[-i-1])
    idea_cipher=final_message[:-count-104]

    #用接收者RSA私钥对rsa_idea_k解密
    idea_k=[]
    for k in rsa_idea_k:
        tmp=myRSA.rsa_decrypt(k, receiver_rsa_d, receiver_rsa_n)
        idea_k.append(tmp)

    #IDEA解密得到zip(<M,S>)保存在re_message.zlib.txt
    zip_message=myIDEA.IDEA_decrypt(idea_k,idea_n,idea_r,idea_cipher)
    f=open('re_message.zlib.txt','wb')
    f.write(zip_message)
    f.close()
    
    #解压缩得到<M,S>，保存在unzip_message.txt
    dst = "unzip_message.txt"
    zip_unzip.decompress('re_message.zlib.txt', dst)
    
    #分解得到数据M和数字签名S
    f=open(dst,'r')
    lines = f.readlines()
    signature=lines[-1]
    M_list=lines[:-1]
    M=''
    for i in M_list:
        M=M+i
    M=M[:-1]
    f.close()    
    print("Signature received by receiver:",int(signature))
    # 验证数字签名
    # 用发送者的RSA公钥解密数字签名S，得到deliver_MD5(M)
    deliver_hash=myRSA.rsa_decrypt(int(signature), deliver_rsa_e, deliver_rsa_n)
    deliver_hash=myRSA.long2mess(deliver_hash)
    print("deliver_hash:",deliver_hash)
    
    #接收者计算接收到的数据M的hash
    receiver_hash=MD5.hash(M)
    print("receiver_hash:",receiver_hash)


if __name__=="__main__":
    #接收方生成RSA密钥对
    t1=time.time()
    receiver_rsa_n,receiver_rsa_e,receiver_rsa_d=receiver_rsa_key()
    t2=time.time()
    receiver_time=t2-t1
    print("receiver_rsa_n:",receiver_rsa_n)
    print("receiver_rsa_e:",receiver_rsa_e)
    print("receiver_rsa_d:",receiver_rsa_d)
    
    #发送方发送文件数据M
    t1=time.time()
    file_path = 'ys168.com.txt'
    final_file,idea_n,idea_r,deliver_rsa_n,deliver_rsa_e=deliver(file_path,receiver_rsa_n,receiver_rsa_e)
    t2=time.time()
    deliver_time=t2-t1
    print("deliver_rsa_n:",deliver_rsa_n)
    print("deliver_rsa_e:",deliver_rsa_e)
    
    #接收方
    t1=time.time()
    receiver(final_file,receiver_rsa_n,receiver_rsa_d,idea_n,idea_r,deliver_rsa_n,deliver_rsa_e)
    t2=time.time()
    receiver_time+=t2-t1
    
    print("deliver_time:",deliver_time)
    print('receiver_time:',receiver_time)