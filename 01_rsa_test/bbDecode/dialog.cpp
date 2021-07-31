#include "dialog.h"
#include "ui_dialog.h"
#include "qscrollbar.h"
#include "qfiledialog.h"
#include "qdebug.h"
#include "qcheckbox.h"
#include "qdesktopservices.h"
#include <QApplication>
#include <QDesktopWidget>
#include "QMouseEvent"
#include <QEventLoop>
#include  "qtimer.h"


#include "openssl/rsa.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


uchar g_public_key[] = "-----BEGIN PUBLIC KEY-----\n" \
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2irHzIQHa5Wl+Lqs1ETTgwl6y\n"\
        "fKvR9qWKPpkvCy72hjkEUDEhLrAT1qjwZY7qG9xWJfJvgzDhyzIbw5+B0V6bhLmq\n"\
        "bBMXYWzLyLu4i/KTSRmQwmRHYkLOSprvUm3XapQonrlnu/YFtAabQf+sZO37Igo/\n"\
        "aPomoR/QOzcw1pdLywIDAQAB\n"\
        "-----END PUBLIC KEY-----";

uchar g_private_key[] = "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICWwIBAAKBgQC2irHzIQHa5Wl+Lqs1ETTgwl6yfKvR9qWKPpkvCy72hjkEUDEh\n"\
        "LrAT1qjwZY7qG9xWJfJvgzDhyzIbw5+B0V6bhLmqbBMXYWzLyLu4i/KTSRmQwmRH\n"\
        "YkLOSprvUm3XapQonrlnu/YFtAabQf+sZO37Igo/aPomoR/QOzcw1pdLywIDAQAB\n"\
        "AoGAEdCfZVcHU1GoZgQv+VHgkz7k9w5rxmYH6eIKGSlCQBUBY4ZgBRkFXipI+o0u\n"\
        "0XI+orm5W2C2WJL4JPWGj6jbTq/uNAFUahVwvI9zcfoaf733vqe50nbHlKlNsg3Q\n"\
        "P4tKTfe2laXs1g4cHLqWquIM1uxkMJwM3qzFAqPjP4lWMAECQQDneinLmw87SXyZ\n"\
        "RI6hzbo60JsCbB+hDnZ/VI0tYukmAuUY+Qf+0S21Qq1ZjxZJlF6VmRvFXNaKhfug\n"\
        "M8QzXZIBAkEAyeFdvmQK9N/TvaJVZlzPHGTz2ZD2lHRnxMbPMUc771H5ULx6IoxE\n"\
        "58jHYDgDGzN3/xvtCQ8I8DCCHjhHyoqFywJAFxBjDbh7ggrGcXcVRyX6glW6vDkN\n"\
        "xbxtLi68imMqm/D55s0ZcNhi14a3Qw8wx1ATRJCm5blkXxUOh13hFMUkAQJAYfA1\n"\
        "fFIohpe3r337lEdeKtZG/ru3BFpcpTgV+EAosXfBTgvB7NTD8PaU0vcZeq7Dfj3c\n"\
        "BtMGcQ/3cBW5rmb5dQJAWa0Pn3HC2rUhcb4ss2vVLr4/Sv+wO8E/hRiNFvKNzDKF\n"\
        "CHKXkdnWPF3FHINGJ7IXt4PkFiZ8S3uEQAoUZljukw==\n"\
        "-----END RSA PRIVATE KEY-----";




#define RSA_LENGTH 1024
// define rsa public key
#define BEGIN_RSA_PUBLIC_KEY    "BEGIN RSA PUBLIC KEY"
#define BEGIN_PUBLIC_KEY        "BEGIN PUBLIC KEY"
/**
 * @brief Dialog::createRSA 载入密钥
 * @param key 密钥
 * @param publi 公钥1 私钥0
 * @return
 */
RSA * Dialog::createRSA(unsigned char * key,int publi)
{
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, strlen((char*)key));
    if (keybio==NULL)
    {
        qDebug()<< "Failed to create key BIO";
        return 0;
    }
    RSA* pRsa = RSA_new();
    if(publi)
    {
        pRsa = PEM_read_bio_RSA_PUBKEY(keybio, &pRsa,NULL, NULL);
    }
    else
    {
        pRsa = PEM_read_bio_RSAPrivateKey(keybio, &pRsa,NULL, NULL);
    }
    if(pRsa == NULL)
    {
        qDebug()<< "Failed to create RSA";
        BIO_free_all(keybio);
    }
    return pRsa;
}
/**
 * @brief Dialog::public_encrypt 公钥加密
 * @param data 待加密数据
 * @param data_len 待加密的数据长度
 * @param key 公钥
 * @param encrypted 加密后的数据
 * @return 加密长度
 */
int Dialog::public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    rsaResult = RSA_public_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING);
    return rsaResult;
}
/**
 * @brief Dialog::private_decrypt 私钥解密
 * @param enc_data 待解密数据
 * @param data_len 待解密数据长度
 * @param key 私钥
 * @param decrypted 解密后的数据
 * @return
 */
int Dialog::private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    int  rsaResult = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,RSA_PKCS1_PADDING);
    return rsaResult;
}
/**
 * @brief Dialog::private_encrypt 私钥加密
 * @param data 待加密数据
 * @param data_len 待加密数据长度
 * @param key 私钥
 * @param encrypted 加密后数据
 * @return
 */
int Dialog::private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    qDebug()<<RSA_size(rsa);
    int rsaResult = RSA_private_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING );
    return rsaResult;
}
/**
 * @brief Dialog::public_decrypt 公钥解密
 * @param enc_data 待解密数据
 * @param data_len 待解密数据长度
 * @param key 公钥
 * @param decrypted 解密后的数据
 * @return
 */
int Dialog::public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    qDebug()<<RSA_size(rsa);
    int  rsaResult = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,RSA_PKCS1_PADDING );
    return rsaResult;
}
/**
 * @brief Dialog::public_encrypt 公钥加密
 * @param data 待加密数据
 * @param keystr 公钥
 * @param encrypted 加密后数据
 * @return
 */
int Dialog::public_encrypt(QString &data,QString &keystr,QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;
    int rsaResult=-1;
//    QByteArray decdata=QByteArray::fromStdString(data.toStdString()).toBase64(QByteArray::Base64Encoding);
    QByteArray decdata=data.toUtf8();
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len>exppadding-11)
        exppadding=exppadding-11;
    int b=0;
    int s=data_len/(exppadding);//片数
    if(data_len%(exppadding))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<exppadding;j++)
        {
            if(i*exppadding+j>data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }
        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_public_encrypt(exppadding,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
        }
        free(smldata);
    }
    QString str(signByteArray.toHex());
    qDebug()<<str;
    encrypted.append(str);
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief Dialog::private_decrypt 私钥解密
 * @param data 待解密数据
 * @param keystr 私钥
 * @param decrypted 解密后的数据
 * @return
 */
int Dialog::private_decrypt(QString &data,QString &keystr,QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int rsaResult=-1;
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    QByteArray signByteArray;
    int data_len=encdata.length();
    int b=0;
    int s=data_len/(rsasize);//片数
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();//(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_private_decrypt(rsasize,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
        }
    }
//    QByteArray b1= QByteArray::fromBase64(signByteArray,QByteArray::Base64Encoding);
    QByteArray b1= signByteArray;
    std::string str=b1.toStdString();
    decrypted.append(QString::fromStdString( str));
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief Dialog::private_encrypt 私钥加密
 * @param data 待加密数据
 * @param keystr 私钥
 * @param encrypted 解密后的数据
 * @return
 */
int Dialog::private_encrypt(QString &data,QString &keystr,QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;
    int rsaResult=-1;
//    QByteArray decdata=QByteArray::fromStdString(data.toStdString()).toBase64(QByteArray::Base64Encoding);
    QByteArray decdata=QByteArray::fromStdString(data.toStdString());
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len>exppadding-11)//padding占11位
        exppadding=exppadding-11;
    int b=0;
    int s=data_len/(exppadding);//片数
    if(data_len%(exppadding))
        s++;
    for(int i=0;i<s;i++)
    {
        //分片加密
        QByteArray subdata;
        subdata.clear();;
        for(int j=0;j<exppadding;j++)
        {
            if(i*exppadding+j>data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }
        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_private_encrypt(exppadding,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
        }
        free(smldata);
    }
    QString str(signByteArray.toHex());
    qDebug()<<str;
    encrypted.append(str);
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief Dialog::public_decrypt 公钥解密
 * @param data 待解密数据
 * @param keystr 公钥
 * @param decrypted 解密后的数据
 * @return
 */
int Dialog::public_decrypt(QString &data,QString &keystr,QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int rsaResult=-1;
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    QByteArray signByteArray;
    int data_len=encdata.length();
    int b=0;
    int s=data_len/(rsasize);//片数
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();//(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_public_decrypt(rsasize,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
        }
    }
//    QByteArray b1= QByteArray::fromBase64(signByteArray,QByteArray::Base64Encoding);
    QByteArray b1=signByteArray;
    std::string str=b1.toStdString();
    decrypted.append(QString::fromStdString( str));
    rsaResult=b;
    return rsaResult;
}

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::CustomizeWindowHint|Qt::FramelessWindowHint);
    QDesktopWidget* desktopWidget = QApplication::desktop();
    QRect clientRect = desktopWidget->availableGeometry();
    this->resize(clientRect.width()/2, clientRect.height()/2);
    ui->pb_add->setFixedSize(clientRect.width()/20,clientRect.height()/30);
    ui->pb_clear->setFixedSize(clientRect.width()/20,clientRect.height()/30);
    ui->pb_start->setFixedSize(clientRect.width()/20,clientRect.height()/30);
    ui->pb_dir->setFixedSize(clientRect.width()/40,clientRect.height()/30);
    ui->le_dir->setFixedSize(clientRect.width()/4,clientRect.height()/30);
    uiInit();
    setStyle(this,"./image/opdetail.qss");
    lastPath = "";
}

Dialog::~Dialog()
{
    delete ui;
}


void Dialog::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        m_Drag = true;
        m_DragPosition = event->globalPos() - this->pos();
        event->accept();
    }
}

void Dialog::mouseMoveEvent(QMouseEvent *event)
{
    if (m_Drag && (event->buttons() && Qt::LeftButton)) {
        move(event->globalPos() - m_DragPosition);
        event->accept();
    }
}

void Dialog::mouseReleaseEvent(QMouseEvent *)
{
    m_Drag = false;

}

void Dialog::uiInit()
{
    ui->lb_logo->setStyleSheet("border-image:url(./image/logo.png);");
    ui->pb_min->setStyleSheet("border-image:url(./image/min.png);");
    ui->pb_close->setStyleSheet("border-image:url(./image/m_close.png);");

    ui->le_dir->setEnabled(false);
    QString path = readFromFile();
    ui->le_dir->setText(tr("%1").arg(path));

    initTable();

}

/*读取样式*/
bool Dialog::setStyle(QWidget *widget, QString qssFile)
{
    if(qssFile.isEmpty() || widget == NULL)
    {
        return false;
    }
    QFile qss(qssFile);
    qss.open(QFile::ReadOnly);
    if(qss.isOpen())
    {
        QString qssstr = QLatin1String(qss.readAll());
        widget->setStyleSheet(qssstr);
        qss.close();
        return true;
    }
    return false;
}

int Dialog::fileDecode(QString fileName)
{
    unsigned short data[1024];
    unsigned short data2[1024];
    char *ch, *cch;
    QStringList nameList = fileName.split("/");
    QByteArray ba = fileName.toLocal8Bit(); // 支持中文，toutf8 不支持中文
    ch=ba.data();

    int readLen = 0;
    int deLen = 0;

    FILE *fp = fopen(ch, "rb");

    QString d_fileName = "";
    d_fileName = tr("%1").arg(ui->le_dir->text())+"d_"+nameList.at(nameList.count()-1);
    qDebug()<<tr("%1").arg(d_fileName);
    QByteArray baa = d_fileName.toLocal8Bit();
    cch=baa.data();

    FILE *fp_e = fopen(cch, "wb+");

    if(NULL != fp && NULL != fp_e)
    {
        fseek (fp , 0 , SEEK_SET);
        fseek (fp_e , 0 , SEEK_SET);
        memset(data, 0, RSA_LENGTH);
        memset(data2, 0, RSA_LENGTH);
        // 加密
//        while(readLen = fread(data, 1, RSA_LENGTH/8-11, fp))
//        {
//            deLen = public_decrypt((uchar*)data, readLen, g_public_key, (uchar*)data2 );
        // 解密
        while(readLen = fread(data, 1, RSA_LENGTH/8, fp))
        {
            deLen = private_decrypt((uchar*)data, readLen, g_private_key, (uchar*)data2 );
            if(deLen < 0)
            {
                qDebug()<<"private_decrpt decode error";
                break;
            }
            fwrite(data2, deLen, 1, fp_e);
            memset(data, 0, RSA_LENGTH);
            memset(data2, 0, RSA_LENGTH);
            if(readLen < RSA_LENGTH/8)
            {
                break;
            }
        }
        fclose(fp_e);
        fclose(fp);
    }

}

void Dialog::decodeUseIndex(int row)
{
    // 开始解密
    ui->tableWidget->item(row,2)->setText(tr("正在解密..."));
    Delay_MSec(100);

    QWidget *w = ui->tableWidget->cellWidget(row, 3);
    QPushButton * pb = qobject_cast<QPushButton*>(w->children().at(1));
    pb->setStyleSheet("border-image:url(./image/stop_1.png);");
    pb->setEnabled(false);
    pb = qobject_cast<QPushButton*>(w->children().at(2));
    pb->setEnabled(false);
    pb = qobject_cast<QPushButton*>(w->children().at(3));
    pb->setStyleSheet("border-image:url(./image/close_1.png);");
    pb->setEnabled(false);

    fileDecode(tr("%1").arg(ui->tableWidget->item(row,4)->text()));





     // 解密完成
    ui->tableWidget->item(row,2)->setText(tr("解密完成"));
    w = ui->tableWidget->cellWidget(row, 3);
    pb = qobject_cast<QPushButton*>(w->children().at(1));
    pb->setEnabled(false);
    pb = qobject_cast<QPushButton*>(w->children().at(2));
    pb->setStyleSheet("border-image:url(./image/folder.png);");
    pb->setEnabled(true);
    pb = qobject_cast<QPushButton*>(w->children().at(3));
    pb->setStyleSheet("border-image:url(./image/close.png);");
    pb->setEnabled(true);
}

void Dialog::showEvent(QShowEvent *)
{

}
QString Dialog::setDir()
{
    QString file_path = QFileDialog::getExistingDirectory(this, "请选择文件路径...", "./");

    if(!file_path.isEmpty())
    {
        return file_path;
    }else
    {
        return "./";
    }

}
void Dialog::initTable()
{
    QHeaderView* headerView = ui->tableWidget->verticalHeader();
    headerView->setHidden(true);
    ui->tableWidget->setColumnCount(5);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectItems);

    ui->tableWidget->setHorizontalHeaderItem(0,new QTableWidgetItem("     "));
    ui->tableWidget->setHorizontalHeaderItem(1,new QTableWidgetItem("文件名"));
    ui->tableWidget->setHorizontalHeaderItem(2,new QTableWidgetItem("状态"));
    ui->tableWidget->setHorizontalHeaderItem(3,new QTableWidgetItem("操作"));
    ui->tableWidget->setHorizontalHeaderItem(4,new QTableWidgetItem("路径"));

    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->horizontalHeader()->setVisible(true);
    // 自由伸缩
//    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    ui->tableWidget->setMouseTracking(true);
    ui->tableWidget->setShowGrid(false);//隐藏网格
    ui->tableWidget->horizontalHeader()->setHighlightSections(false);//表头不塌陷
    ui->tableWidget->horizontalHeader()->setSectionsClickable(false);
    ui->tableWidget->verticalScrollBar()->setContextMenuPolicy(Qt::NoContextMenu);
    ui->tableWidget->horizontalScrollBar()->setContextMenuPolicy(Qt::NoContextMenu);
    ui->tableWidget->horizontalHeader()->setMinimumHeight(30);
    ui->tableWidget->hideColumn(4);

    connect(this, SIGNAL(sig_fileName(QString)),this,SLOT(addFileToTable(QString)));

}

void Dialog::on_pb_min_clicked()
{
    this->showMinimized();
}

void Dialog::on_pb_close_clicked()
{
    this->close();
}

void Dialog::on_pb_add_clicked()
{
    QString addPath = "";
    if(lastPath == "")
    {
        addPath = "./";
    }else
    {
        addPath = lastPath;
    }
    qDebug()<<"on_pb_add_clicked"<<addPath;
    QString fileName = QFileDialog::getOpenFileName(NULL,tr("添加文件"), tr("%1").arg(addPath), "File (*.csv)");
    if(""!=fileName )
    {
        emit sig_fileName(fileName);
    }

//    qDebug()<<fileName
//    return fileName;
}

void Dialog::on_pb_clear_clicked()
{
    for(int i = ui->tableWidget->rowCount() -1 ; i>=0;i--)
    {
        ui->tableWidget->removeRow(i);
    }
}

void Dialog::addFileToTable(QString fileName)
{
    qDebug()<<fileName;
    QStringList list = fileName.split("/");
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    int index = ui->tableWidget->rowCount()-1;

    QCheckBox *cb = new QCheckBox("");
    QWidget* pWidget = new QWidget();
    QHBoxLayout* pLayout = new QHBoxLayout(pWidget);
    pLayout->addWidget(cb);
    pLayout->setAlignment(Qt::AlignCenter);
    pLayout->setContentsMargins(0, 0, 0, 0);
    pWidget->setLayout(pLayout);

    ui->tableWidget->setCellWidget(index,0,pWidget);
    QString file = list.at(list.count()-1);
    ui->tableWidget->setItem(index, 1, new QTableWidgetItem(list.at(list.count()-1)));
    lastPath = fileName.left(fileName.length() - file.length());
    ui->tableWidget->setItem(index, 2, new QTableWidgetItem("未解密"));

    QPushButton *btn_restart = new QPushButton();
    btn_restart->setMaximumSize(20,20);
    btn_restart->setStyleSheet("border-image:url(./image/restart.png);");

    QPushButton *btn_forder = new QPushButton();
    btn_forder->setMaximumSize(20,20);
    btn_forder->setStyleSheet("border-image:url(./image/folder_1.png);");

    QPushButton *btn_close_1 = new QPushButton();
    btn_close_1->setMaximumSize(20,20);
    btn_close_1->setStyleSheet("border-image:url(./image/close.png);");

//    QPushButton *btn_2 = new QPushButton();
//    btn_2->setText(tr("修改"));
    QWidget *tmp_widget = new QWidget();
    QHBoxLayout *tmp_layout = new QHBoxLayout(tmp_widget);
    tmp_layout->addWidget(btn_restart);
    tmp_layout->addSpacing(10);
    tmp_layout->addWidget(btn_forder);
    tmp_layout->addSpacing(10);
    tmp_layout->addWidget(btn_close_1);
    tmp_layout->setAlignment(Qt::AlignCenter);
//       tmp_layout->addWidget(btn_2);
    tmp_layout->setContentsMargins(0, 0, 0, 0);
    ui->tableWidget->setCellWidget(index,3,tmp_widget);
    ui->tableWidget->setItem(index, 4, new QTableWidgetItem(fileName));
;

    ui->tableWidget->item(index, 1)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
    ui->tableWidget->item(index, 2)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);
//    ui->tableWidget->item(index, 3)->setTextAlignment(Qt::AlignHCenter|Qt::AlignVCenter);

    btn_restart->setObjectName("select");
    btn_restart->setProperty("index",index);

    btn_forder->setObjectName("select");
    btn_forder->setProperty("index",index);

    btn_close_1->setObjectName("select");
    btn_close_1->setProperty("index",index);

    connect(btn_restart, SIGNAL(clicked()), this, SLOT(restartClicked()));
    connect(btn_forder, SIGNAL(clicked()), this, SLOT(folderClicked()));
    connect(btn_close_1, SIGNAL(clicked()), this, SLOT(close_1Clicked()));

}

void Dialog::Delay_MSec(unsigned int msec)
{
    QEventLoop loop;//定义一个新的事件循环
    QTimer::singleShot(msec, &loop, SLOT(quit()));//创建单次定时器，槽函数为事件循环的退出函数
    loop.exec();//事件循环开始执行，程序会卡在这里，直到定时时间到，本循环被退出
}

void Dialog::restartClicked()
{
    int row = 0;
    QPushButton *senderObj = qobject_cast<QPushButton*>(sender());
    if(senderObj == Q_NULLPTR)
    {
        return;
    }
    qDebug()<<(tr("restartClicked row [%1]").arg(senderObj->property("index").toString()));
    if(!senderObj->property("index").toString().isEmpty())
    {
        row = senderObj->property("index").toInt();
    }

    decodeUseIndex(row);
}

void Dialog::folderClicked()
{
    int row = 0;
    QPushButton *senderObj = qobject_cast<QPushButton*>(sender());
    if(senderObj == Q_NULLPTR)
    {
        return;
    }
    qDebug()<<(tr("folderClicket row [%1]").arg(senderObj->property("index").toString()));
    if(!senderObj->property("index").toString().isEmpty())
    {
        row = senderObj->property("index").toInt();
    }
    QString tmpFile = ui->tableWidget->item(row,1)->text();
    QString tmpFileDir = ui->tableWidget->item(row,4)->text();
    int dirLen = tmpFileDir.length();
    QString fileDir = tmpFileDir.left(dirLen -1 -tmpFile.length());
    qDebug()<<"folderClicked"<<fileDir;
    QDesktopServices::openUrl(QUrl::fromLocalFile(fileDir));

}


QString Dialog::readFromFile()
{
    QString path = "./config/path.ini";
    QStringList list;
    QFile file(path);
    if(!file.exists()) return "";
    if(file.open(QIODevice::ReadOnly))
    {
        QString tmp;
        QString data = tmp.prepend(file.readAll());
        list = data.split("\n");

        file.close();

    }
    if(list.count())
    {
        return list.at(0);
    }else
    {
        return "";
    }
}

void Dialog::writeToFile(QString outPath)
{
    QString path="./config/path.ini";
    QFile file(path);
    if(file.open(QIODevice::WriteOnly))
    {
        QTextStream out(&file);
        out.setCodec("utf-8");
        out<<outPath<<"\n";
        file.close();
    }
}

void Dialog::close_1Clicked()
{
    int row = 0;
    QPushButton *senderObj = qobject_cast<QPushButton*>(sender());
    if(senderObj == Q_NULLPTR)
    {
        return;
    }
    qDebug()<<(tr("close_1Clicked row [%1]").arg(senderObj->property("index").toString()));
    if(!senderObj->property("index").toString().isEmpty())
    {
        row = senderObj->property("index").toInt();
    }

    ui->tableWidget->removeRow(row);

}

void Dialog::on_pb_start_clicked()
{

    for(int i = ui->tableWidget->rowCount() -1 ; i>=0;i--)
    {
        QWidget *w = ui->tableWidget->cellWidget(i, 0);
        // qobject_cast<QComboBox*>(tb_Device->cellWidget(index, MAIN_AutoBtn))
        QCheckBox * checkBox = qobject_cast<QCheckBox*>(w->children().at(1));
        if(checkBox->checkState() == Qt::Checked)
        {
            decodeUseIndex(i);
            checkBox->setChecked(Qt::Unchecked);
        }
    }
}

void Dialog::on_pb_dir_clicked()
{
    QString path = setDir()+"/";
    ui->le_dir->setText(tr("%1").arg(path));
    writeToFile(tr("%1").arg(path));
}
