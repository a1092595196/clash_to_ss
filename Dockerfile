cat Dockerfile 
# 使用官方Python基础镜像  
#FROM registry.cn-chengdu.aliyuncs.com/2631f/linux_arm64_python:3.8
FROM python:3.8
  # 设置工作目录  
  WORKDIR /usr/src/app
    # 复制当前目录下的文件到工作目录  
    COPY . .
      # 安装requests库  
      RUN pip install requests
