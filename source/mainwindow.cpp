#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDateTime>
#include <QKeyEvent>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(&thread, SIGNAL(connectionEstablished(int, QString, QString, QString)), this, SLOT(connectionEstablishedSlot(int, QString, QString, QString)));
    connect(&thread, SIGNAL(receiveMessage(QString)), this, SLOT(receiveMessageSlot(QString)));
    connect(&thread, SIGNAL(negotiationComplete(int, int, unsigned char*)), this, SLOT(negotiationCompleteSlot(int, int, unsigned char*)));
    ui->textBrowser->append("Setting up the connection...");
    thread.start();
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    QString texta = ui->plainTextEdit->toPlainText();
    if (texta.size() > 0) {
        unsigned char data_to_encrypt[16];
        unsigned char data_after_encrypt[16];
        unsigned long fsize;
        FILE* fp;
        // jwj work
        BYTE buf[SHA256_BLOCK_SIZE];
        BYTE * text;
        CTX ctx;
        unsigned char shaPath[4097] = "sha256.txt";
        unsigned long shaSize;
        int i;
        FILE * sha;
        // jwj work
        while((fp=fopen("send.tmp","w"))==NULL){
            qDebug() << "file write error!\n";
            exit(0);
        }
        fputs(texta.toStdString().c_str(),fp);
        fclose(fp);
        while((fp=fopen("send.tmp","rb"))==NULL){
            qDebug() << "file error!\n";
            exit(0);
        }
        //printf("File opening...\n");
        fseek(fp,SEEK_SET,SEEK_END);
        fsize=ftell(fp);
        fseek(fp,0,SEEK_SET);
        // jwj work
        text = (BYTE *)malloc((fsize + 1) * sizeof(char)); // 因为 BYTE 就是 unsigned char 感觉没什么问题
        fsize = fread(text, 1, fsize, fp);
        text[fsize] = '\0';
        // 进行 hash 散列值计算
        sha256_init(&ctx);
        sha256_update(&ctx, text, fsize);
        sha256_final(&ctx, buf);
        fseek(fp,0,SEEK_SET);
        printf("sha256: 0x");
        sha = fopen("./sha256.txt", "w");
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            printf("%x", buf[i]);
            fprintf(sha, "%x", buf[i]);
        }
        fclose(sha);
        free(text);
        sha = fopen("./sha256.txt", "rb");
        fseek(sha,SEEK_SET,SEEK_END);
        shaSize=ftell(sha);
        fseek(sha,0,SEEK_SET);
        memset(data_to_encrypt,0,sizeof(data_to_encrypt));
        sendFile(sha, shaSize, shaPath, data_to_encrypt, data_after_encrypt,AESEncryptKey,sock);
        printf("sha path:%s\n", shaPath);
        fclose(sha);
        // jwj work
        memset(data_to_encrypt,0,sizeof(data_to_encrypt));
        unsigned char aapath[10] = "send.tmp";
        sendFile(fp, fsize, aapath, data_to_encrypt, data_after_encrypt, AESEncryptKey, sock);
        fclose(fp);
        QDateTime curDateTime = QDateTime::currentDateTime();
        ui->textBrowser->append("You  " + curDateTime.toString("yyyy-MM-dd hh:mm:ss"));
        ui->textBrowser->append(texta);
        ui->plainTextEdit->clear();
    }
}

void MainWindow::connectionEstablishedSlot(int state, QString ipAddr, QString port, QString mode)
{
    sock = state;
    if (state < 0) {
        ui->textBrowser->append("Connection failed!");
    } else {
        ui->textBrowser->append("Connection established!");
        ui->label->setText("Connect on server " + ipAddr + ":" + port + ", your mode: " + mode);
        ui->pushButton->setEnabled(true);
    }
}

void MainWindow::receiveMessageSlot(QString qstr)
{
    QDateTime curDateTime = QDateTime::currentDateTime();
    ui->textBrowser->append("Peer  " + curDateTime.toString("yyyy-MM-dd hh:mm:ss"));
    ui->textBrowser->append(qstr);
}

void MainWindow::negotiationCompleteSlot(int _servSock, int _sock, unsigned char* _AESEncryptKey)
{
    servSock = _servSock;
    sock = _sock;
    AESEncryptKey = _AESEncryptKey;
}
