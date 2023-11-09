#   导入qt包
from PySide6 import QtWidgets
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtWidgets import *
#   导入scapy包
from scapy.arch.windows import get_windows_if_list
from scapy.all import *
import threading


class Sniffer(QObject):
    # 自定义信号
    new_packet_signal = Signal(list)                  # 代表新的包到来的信号
    packet_hex_signal = Signal(str)                   # 代表包的十六进制信息的信号
    packet_protocol_signal = Signal(list)             # 代表包的各层信息的信号

    def __init__(self):
        super().__init__()
        # 接口名称列表
        self.interface_names_list = []
        # 代表过滤条件
        self.filter_condition = ""
        # 代表要捕获的网络接口
        self.misc_interface = ""
        # 代表所抓取的包的序号
        self.index = 0
        # 代表关于的信息
        self.about = ("高行政 软件与系统安全作业 2023E8013382016\n\n"
                      "网络嗅探器 version 0.0.1\n\n"
                      "图片来源于百度，侵权删除!\n\n")
        # 代表图像路径
        self.imagePath = "images/icon.jpeg"
        # 代表每个数据包的各层信息
        self.packet_layers = []
        # 创建锁（解决抓包时线程安全问题）
        self.lock = threading.Lock()
        # 代表所有抓取的包的大致信息
        self.captured_packets = []
        # 代表所有抓取包的十六进制信息
        self.hex_contents = []
        # 代表重新开始嗅探的标志
        self.re_sniff_flag = False
        # 代表sniff函数线程
        self.thread_sniff = None
        # 进行初始化
        self.program_init()

    # 代表进行初始化的函数
    def program_init(self):
        self.get_interface()

    # 代表获得网卡名称的函数
    def get_interface(self):
        #   获取网卡名称信息，并存入列表
        for interface in get_windows_if_list():
            self.interface_names_list.append(interface.get('name'))

    # 更改sniff网卡参数
    def update_interface_name(self, text):
        self.misc_interface = text

    # 更改sniff嗅探规则参数
    def update_filter_content(self, text):
        self.filter_condition = text

    # 获取包的各个层的生成器函数（从底层到高层）
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

    # 将包的总体数据回显在页面上
    @Slot(list)
    def print_packet_to_gui(self,pkt):
        # 插入新行
        self.packetWidget.insertRow(self.index - 1)
        # 在行中添加列
        for cnt,item in enumerate(pkt):
            table_widget_item = QTableWidgetItem(str(item))
            self.packetWidget.setItem(self.index - 1,cnt,table_widget_item)
        # 处理线程安全问题
        self.lock.release()

    # 获取包所在的行
    def get_packet_row(self,msg):
        # 每次添加数据之前，先进行数据的清空
        self.hexEdit.setText("")
        # 回显之前，先清空根节点及子节点
        self.detailWidget.clear()
        # 获取包的行
        packet_row = msg.row()
        # 提取出包的十六进制数据，进行页面回显
        self.packet_hex_signal.emit(self.hex_contents[packet_row])
        # 提取出包的各层数据，进行页面回显
        self.packet_protocol_signal.emit(self.packet_layers[packet_row])

    # 将包的十六进制信息回显在页面上
    def print_packet_hex_to_gui(self,msg):
        # 添加数据
        self.hexEdit.append(msg)

    # 将包的各层信息回显在页面上
    def print_packet_protocol_to_gui(self,layers):
        # 如果该层信息不存在
        if len(layers) == 0:
            return
        # 遍历每一层，开始显示信息
        for current_layer in layers:
            # 创建根节点
            root_item_protocol = QTreeWidgetItem(self.detailWidget)
            root_item_protocol.setText(0,current_layer.name)
            # 根据各层数据，创建子节点
            for key,value in current_layer.fields.items():
                # 创建子节点
                child_item_protocol = QTreeWidgetItem(root_item_protocol)
                # 给子节点设置值
                child_item_protocol.setText(0,str(key))
                child_item_protocol.setText(1,str(value))
                # 将子节点添加到根节点中
                root_item_protocol.addChild(child_item_protocol)

    # 代表清空所有数据的函数
    def all_clear(self):
        self.packet_layers = []
        self.captured_packets = []
        self.hex_contents = []
        self.detailWidget.clear()
        self.packetWidget.clearContents()
        self.hexEdit.clear()
        self.index = 0

    # 代表捕获数据包的回调函数
    def packet_handler(self, packet):
        # 处理线程安全问题（使得必须以先抓包再添加的顺序执行）
        self.lock.acquire()
        # 处理捕获到的数据包
        self.index = self.index + 1
        captured_packet = []
        # 将抓包的时间戳转换成容易阅读的时间格式
        formatted_time = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
        # 获取所抓取的包的源地址
        source_ip = packet['IP'].src
        # 获取所抓取的包的目的地址
        destination_ip = packet['IP'].dst
        # 获取所抓取包的各层协议对象（list）
        layers = list(self.get_packet_layers(packet))
        self.packet_layers.append(layers)
        layer_names = [item.name for item in self.get_packet_layers(packet)]
        # 获取包的最高层
        for i in range(0,len(layer_names),1):
            if layer_names[i] == 'Raw' or layer_names[i] == 'Padding':
                continue
            maximum_layer_protocol = layer_names[i]
        # 获取所抓取的包的总长度(头部 + 负载)
        total_length = len(packet)
        # 获取所抓取的包的摘要信息
        packet_info = packet.summary()
        # 将上述信息进行获取，并存储在列表中
        captured_packet.extend(
            [self.index, formatted_time,
             source_ip, destination_ip,
             maximum_layer_protocol,
             total_length, packet_info])
        self.captured_packets.append(captured_packet)
        self.hex_contents.append(hexdump(packet,True))
        # 发出信号
        self.new_packet_signal.emit(captured_packet)
        # 获取所抓取每个包的十六进制信息
        self.hex_data = hexdump(packet, True)

    # 代表开始嗅探的函数
    def start_sniff(self):
        # 条件过滤
        if self.misc_interface == "":
            # TODO
            pass
            return
        if self.filter_condition == "":
            # TODO
            pass
            return
        # 一旦开始嗅探，不可再次选择网卡和过滤条件
        self.lineEdit.setReadOnly(True)             # 只能只读
        self.comboBox.setEnabled(False)             # 禁用下拉选项

        # 使用异步的sniff函数对指定的网络接口捕获数据包
        self.thread_sniff = AsyncSniffer(iface=self.misc_interface,prn=self.packet_handler,filter=self.filter_condition)
        self.thread_sniff.start()

    # 代表重新开始嗅探的函数
    def re_sniff(self):
        self.thread_sniff.stop()
        self.all_clear()
        self.thread_sniff.start()

    # 代表回显关于信息
    def print_menu_about_to_gui(self):
        dialog = QDialog()                                     # 声明对话框
        dialog.setWindowTitle("About")
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        dialog.setLayout(layout)
        icon_pixmap = QPixmap(self.imagePath)
        scaled_icon_pixmap = icon_pixmap.scaled(200,200)       # 调整图片大小
        icon_label = QLabel()
        icon_label.setPixmap(scaled_icon_pixmap)               # 显示头像
        label = QLabel(self.about)                             # 显示关于信息
        layout.addWidget(label)
        layout.addWidget(icon_label)
        dialog.resize(400,300)
        dialog.exec()

    # 代表进行退出
    def exit_to_gui(self):
        app.quit()

    # 代表统一连接槽函数的函数
    def connect_solt_functions(self):
        # 槽函数及自定义信号槽函数部分
        self.comboBox.currentTextChanged.connect(self.update_interface_name)    # 当选择网卡时，触发槽函数，更改sniff参数
        self.lineEdit.textChanged.connect(self.update_filter_content)           # 当输入框内容变化时，连接槽函数
        self.pushButton.clicked.connect(self.start_sniff)                       # 连接槽函数(开始嗅探)
        self.pushButton_2.clicked.connect(self.re_sniff)                        # 连接槽函数(重新开始嗅探)
        self.packetWidget.clicked.connect(self.get_packet_row)                  # 连接槽函数(获取每个包所在的行)
        self.new_packet_signal.connect(self.print_packet_to_gui)                # 在gui中回显总体包信息
        self.packet_hex_signal.connect(self.print_packet_hex_to_gui)                 # 在gui中回显包的十六进制数据
        self.packet_protocol_signal.connect(self.print_packet_protocol_to_gui)       # 在gui中回显包的各层数据
        self.actionAbout.triggered.connect(self.print_menu_about_to_gui)             # 在gui中回显关于信息
        self.actionExit.triggered.connect(self.exit_to_gui)                          # 在gui中进行退出

    # 启动gui
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(942, 671)
        self.actionAbout = QAction(MainWindow)
        self.actionAbout.setObjectName(u"actionAbout")
        self.actionAbout.setCheckable(False)
        self.actionExit = QAction(MainWindow)
        self.actionExit.setObjectName(u"actionExit")
        self.actionExit.setCheckable(False)
        self.actionExit.setChecked(False)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.widget = QWidget(self.centralwidget)
        self.widget.setObjectName(u"widget")
        self.widget.setStyleSheet(u"background-color:white")
        self.gridLayout_2 = QGridLayout(self.widget)
        self.gridLayout_2.setObjectName(u"gridLayout_2")
        self.widget_5 = QWidget(self.widget)
        self.widget_5.setObjectName(u"widget_5")
        self.gridLayout_3 = QGridLayout(self.widget_5)
        self.gridLayout_3.setObjectName(u"gridLayout_3")
        self.NicLabel = QLabel(self.widget_5)
        self.NicLabel.setObjectName(u"NicLabel")
        sizePolicy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.NicLabel.sizePolicy().hasHeightForWidth())
        self.NicLabel.setSizePolicy(sizePolicy)
        self.gridLayout_3.addWidget(self.NicLabel, 0, 0, 1, 1)
        self.comboBox = QComboBox(self.widget_5)
        self.comboBox.setPlaceholderText("请选择您需要的网卡")  # 设置提示信息
        self.comboBox.addItems(self.interface_names_list)    # 添加网卡项
        self.comboBox.setObjectName(u"comboBox")
        self.gridLayout_3.addWidget(self.comboBox, 0, 1, 1, 1)
        self.gridLayout_2.addWidget(self.widget_5, 0, 0, 1, 1)
        self.widget_6 = QWidget(self.widget)
        self.widget_6.setObjectName(u"widget_6")
        self.gridLayout_4 = QGridLayout(self.widget_6)
        self.gridLayout_4.setObjectName(u"gridLayout_4")
        self.label = QLabel(self.widget_6)
        self.label.setObjectName(u"label")
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.gridLayout_4.addWidget(self.label, 0, 0, 1, 1)
        self.lineEdit = QLineEdit(self.widget_6)
        self.lineEdit.setObjectName(u"lineEdit")
        self.lineEdit.setPlaceholderText("请输入您需要的过滤规则")  # 给输入框设置提示信息
        self.gridLayout_4.addWidget(self.lineEdit, 0, 1, 1, 1)
        self.pushButton = QPushButton(self.widget_6)
        self.pushButton.setObjectName(u"pushButton")
        sizePolicy.setHeightForWidth(self.pushButton.sizePolicy().hasHeightForWidth())
        self.pushButton.setSizePolicy(sizePolicy)
        self.gridLayout_4.addWidget(self.pushButton, 0, 2, 1, 1)
        self.pushButton_2 = QPushButton(self.widget_6)
        self.pushButton_2.setObjectName(u"pushButton_2")
        sizePolicy.setHeightForWidth(self.pushButton_2.sizePolicy().hasHeightForWidth())
        self.pushButton_2.setSizePolicy(sizePolicy)
        self.gridLayout_4.addWidget(self.pushButton_2, 0, 3, 1, 1)
        self.gridLayout_2.addWidget(self.widget_6, 1, 0, 1, 1)
        self.gridLayout.addWidget(self.widget, 0, 0, 1, 1)
        self.detailWidget = QTreeWidget(self.centralwidget)
        self.detailWidget.setObjectName(u"detailWidget")
        self.detailWidget.setHeaderHidden(True)                 # 将表头隐藏
        self.detailWidget.setColumnCount(2)                     # 设置列数
        self.gridLayout.addWidget(self.detailWidget, 3, 0, 1, 1)
        self.hexEdit = QTextEdit(self.centralwidget)
        self.hexEdit.setObjectName(u"hexEdit")
        self.gridLayout.addWidget(self.hexEdit, 4, 0, 1, 1)
        self.packetWidget = QTableWidget(self.centralwidget)
        if (self.packetWidget.columnCount() < 7):
            self.packetWidget.setColumnCount(7)
        __qtablewidgetitem = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(5, __qtablewidgetitem5)
        __qtablewidgetitem6 = QTableWidgetItem()
        self.packetWidget.setHorizontalHeaderItem(6, __qtablewidgetitem6)
        self.packetWidget.setObjectName(u"packetWidget")
        sizePolicy1 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.packetWidget.sizePolicy().hasHeightForWidth())
        self.packetWidget.setSizePolicy(sizePolicy1)
        self.packetWidget.horizontalHeader().setVisible(True)
        self.packetWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.packetWidget.verticalHeader().setStretchLastSection(True)
        self.packetWidget.horizontalHeader().setStretchLastSection(True)  # 设置表头，拉伸最后一列
        self.gridLayout.addWidget(self.packetWidget, 1, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 942, 23))
        self.menuAbout = QMenu(self.menubar)
        self.menuAbout.setObjectName(u"menuAbout")
        self.menuFile = QMenu(self.menubar)
        self.menuFile.setObjectName(u"menuFile")
        MainWindow.setMenuBar(self.menubar)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuAbout.menuAction())
        self.menuAbout.addAction(self.actionAbout)
        self.menuFile.addAction(self.actionExit)
        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)
        # 进行连接
        self.connect_solt_functions()
        # 设置按钮名称
        self.pushButton_2.setText("重新开始嗅探")


    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.actionAbout.setText(QCoreApplication.translate("MainWindow", u"About", None))
        self.actionExit.setText(QCoreApplication.translate("MainWindow", u"Exit", None))
        self.NicLabel.setText(QCoreApplication.translate("MainWindow", u"\u7f51\u5361\u9009\u62e9\uff1a", None))
        self.label.setText(QCoreApplication.translate("MainWindow", u"\u8fc7\u6ee4\u89c4\u5219\uff1a", None))
        self.pushButton.setText(QCoreApplication.translate("MainWindow", u"\u5f00\u59cb\u55c5\u63a2", None))
        self.pushButton_2.setText(QCoreApplication.translate("MainWindow", u"\u505c\u6b62\u55c5\u63a2", None))
        self.hexEdit.setHtml(QCoreApplication.translate("MainWindow",
                                                        u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                        "p, li { white-space: pre-wrap; }\n"
                                                        "</style></head><body style=\" font-family:'SimSun'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
                                                        "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>",
                                                        None))
        ___qtablewidgetitem = self.packetWidget.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"Id", None));
        ___qtablewidgetitem1 = self.packetWidget.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"Time", None));
        ___qtablewidgetitem2 = self.packetWidget.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"Source", None));
        ___qtablewidgetitem3 = self.packetWidget.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("MainWindow", u"Destination", None));
        ___qtablewidgetitem4 = self.packetWidget.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("MainWindow", u"Protocol", None));
        ___qtablewidgetitem5 = self.packetWidget.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("MainWindow", u"Length", None));
        ___qtablewidgetitem6 = self.packetWidget.horizontalHeaderItem(6)
        ___qtablewidgetitem6.setText(QCoreApplication.translate("MainWindow", u"Info", None));
        self.menuAbout.setTitle(QCoreApplication.translate("MainWindow", u"Help", None))
        self.menuFile.setTitle(QCoreApplication.translate("MainWindow", u"File", None))


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)      # 创建一个QApplication，也就是你要开发的软件app
    MainWindow = QtWidgets.QMainWindow()        # 创建一个QMainWindow，用来装载你需要的各种组件、控件
    ui = Sniffer()                              # ui是你创建的ui类的实例化对象
    ui.setupUi(MainWindow)                      # 执行类中的setupUi方法，方法的参数是第二步中创建的QMainWindow
    # TODO
    MainWindow.setWindowTitle("网络嗅探器")  # 设置qt程序标题
    MainWindow.show()                           # 执行QMainWindow的show()方法，显示这个QMainWindow
    app.exec()                                  # 使用exit()或者点击关闭按钮退出QApplication
