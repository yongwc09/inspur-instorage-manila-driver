INSPUR InStorage Manila 驱动使用说明
=================================
本驱动包实现了Pike版本对 InStorage 存储的支持。

各版本OpenStack驱动部分变化影响
---------------------------------------------
- Pike


使用说明
--------

存储配置
--------
1. 存储初始化。
2. 配置NAS集群，启动NAS服务，启动NFS，CIFS服务，配置NAS端口IP地址（参考存储使用手册)

安装与使用该驱动
----------------
1. 执行 ./mkpackage.sh -t X 生成X版本OpenStack对应的驱动包。X 为 OpenStack 对应版本首字母。
   ```
   ./mkpackage.sh -t X
   ```
2. 将生成驱动包中的inspur目录放置到manila服务安装目录的驱动插件目录下.
   ```
   cp -rf InStorage_XXX_manila/inspur [PATH/TO/MANILA]/share/drivers
   ```
3. 从Pike版本开始, Manila服务中增加了opts.py文件，该文件包含了配置参数相关的处理。需要使用驱动包中的opts.py文件替换manila服务安装目录的opts.py文件中
   ```
   cp -rf InStorage_XXX_manila/opts.py [PATH/TO/MANILA]/opts.py
   ```
4. 修改相关服务配置文件(所有配置改动均需要重启对应服务来使的新配置生效)

   a. Manila服务配置 /etc/manila/manila.conf
      ```
      #修改enable_backends配置,增加INSTORAGE
      enable_backends=[OTHERS],INSTORAGE

      #增加存储后端

      [INSTORAGE]
      #NAS驱动
      share_driver = manila.share.drivers.inspur.instorage.instorage.InStorageShareDriver
      #存储的IP地址
      instorage_nas_ip = 192.168.1.1 
      #存储管理员用户名
      instorage_nas_login = [SUPERUSER]
      #存储管理员用户密码
      instorage_nas_password = [PASSWORD]
      #后端名称
      volume_backend_name = INSTORAGE

      ```

5. 在OpenStack环境中增加卷类型
   ```
   manila type-create inspur

   manila type-key set share_backend_name=INSTORAGE
   
   ```
   之后便可使用该卷类型创建卷
