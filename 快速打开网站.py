import webbrowser

def func(i):
    webbrowser.open(i)


def sitee():
    while 1:

        print('''快速打开以下网站
        1.
        2.
        
        q:退出
        ''')
        dict = {
            "1" : r"",
            "2" : r"",
            "3" : r"",
            "4" : r"",
            "5" : r"",
            "6" : r"",
            "7" : r"",
            "8" : r"",
            "9" : r"",
            "10" : r"",
            #不用的一定要注释掉

        }
        inputt = input("请选择想要打开的网站").lower().strip()
        if inputt == "q":
            break
        elif inputt in dict:
            func(dict[inputt])
        else:
            print('=============尚未添加其他内容=================')
if __name__ == '__main__':
    sitee()